/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dnsdist-async.hh"
#include "dnsdist-internal-queries.hh"
#include "dolog.hh"

namespace dnsdist
{

AsynchronousHolder::AsynchronousHolder(bool failOpen)
{
  d_data = std::make_shared<Data>();
  d_data->d_failOpen = failOpen;

  std::thread main([data = this->d_data] { mainThread(data); });
  main.detach();
}

AsynchronousHolder::~AsynchronousHolder()
{
  try {
    stop();
  }
  catch (...) {
  }
}

void AsynchronousHolder::stop()
{
  {
    auto content = d_data->d_content.lock();
    d_data->d_done = true;
  }
  d_data->d_cond.notify_one();
}

void AsynchronousHolder::mainThread(std::shared_ptr<Data> data)
{
  while (true) {
    /* this construct is a bit weird but we need that
       to get a unique_lock below */
    auto content = data->d_content.try_lock();
    if (!content.owns_lock()) {
      content.lock();
    }

    auto& lock = content.getUniqueLock();
    if (data->d_done) {
      return;
    }

    if (content->empty()) {
      data->d_cond.wait(lock, [&content, &data] { return data->d_done || !content->empty(); });
    }
    else {
      struct timeval now;
      gettimeofday(&now, nullptr);
      struct timeval next = getNextTTD(*content);
      next = next - now;
      uint64_t milli = std::round(uSec(next) / 1000.0);
      auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(milli);

      auto why = data->d_cond.wait_until(lock, until);
      if (data->d_done) {
        return;
      }

      if (why == std::cv_status::timeout && !content->empty()) {
        handleExpired(*content, data->d_failOpen);
      }
    }
  }
}

void AsynchronousHolder::push(uint16_t asyncID, uint16_t queryID, const struct timeval& ttd, std::unique_ptr<CrossProtocolQuery>&& query)
{
  {
    auto content = d_data->d_content.lock();
    content->insert({std::move(query), ttd, asyncID, queryID});
  }
  d_data->d_cond.notify_one();
}

std::unique_ptr<CrossProtocolQuery> AsynchronousHolder::get(uint16_t asyncID, uint16_t queryID)
{
  /* no need to notify, worst case the thread wakes up for nothing because this was the next TTD */
  auto content = d_data->d_content.lock();
  auto it = content->find(std::tie(queryID, asyncID));
  if (it == content->end()) {
    struct timeval now;
    gettimeofday(&now, nullptr);
    vinfolog("Asynchronous object %d not found at %d.%d", queryID, now.tv_sec, now.tv_usec);
    return nullptr;
  }

  auto result = std::move(it->d_query);
  content->erase(it);
  return result;
}

void AsynchronousHolder::handleExpired(content_t& content, bool failOpen)
{
  struct timeval now;
  gettimeofday(&now, nullptr);

  auto& idx = content.get<TTDTag>();
  for (auto it = idx.begin(); it != idx.end() && it->d_ttd < now;) {
    auto queryID = it->d_queryID;
    auto query = std::move(it->d_query);
    it = idx.erase(it);

    if (!failOpen) {
      vinfolog("Asynchronous query %d has expired at %d.%d, notifying the sender", queryID, now.tv_sec, now.tv_usec);
      auto sender = query->getTCPQuerySender();
      if (sender) {
        sender->notifyIOError(std::move(query->query.d_idstate), now);
      }
    }
    else {
      vinfolog("Asynchronous query %d has expired at %d.%d, resuming", queryID, now.tv_sec, now.tv_usec);
      resumeQuery(std::move(query));
    }
  }
}

struct timeval AsynchronousHolder::getNextTTD(const content_t& content)
{
  if (content.empty()) {
    throw std::runtime_error("AsynchronousHolder::getNextTTD() called on an empty holder");
  }

  return content.get<TTDTag>().begin()->d_ttd;
}

bool AsynchronousHolder::empty()
{
  return d_data->d_content.read_only_lock()->empty();
}

static bool resumeResponse(std::unique_ptr<CrossProtocolQuery>&& response)
{
  try {
    auto& ids = response->query.d_idstate;
    DNSResponse dr(ids, response->query.d_buffer, response->downstream);

    auto result = processResponseAfterRules(response->query.d_buffer, dr, ids.cs->muted);
    if (!result) {
      /* easy */
      return false;
    }

    auto sender = response->getTCPQuerySender();
    if (sender) {
      struct timeval now;
      gettimeofday(&now, nullptr);

      TCPResponse resp(std::move(response->query.d_buffer), std::move(response->query.d_idstate), nullptr);
      resp.d_async = true;
      sender->handleResponse(now, std::move(resp));
    }
  }
  catch (const std::exception& e) {
    vinfolog("Got exception while resuming cross-protocol response: %s", e.what());
    return false;
  }

  return true;
}

bool resumeQuery(std::unique_ptr<CrossProtocolQuery>&& query)
{
  if (query->isResponse) {
    return resumeResponse(std::move(query));
  }

  auto& ids = query->query.d_idstate;
  DNSQuestion dq(ids, query->query.d_buffer);
  LocalHolders holders;

  auto result = processQueryAfterRules(dq, holders, query->downstream);
  if (result == ProcessQueryResult::Drop) {
    /* easy */
    return false;
  }
  else if (result == ProcessQueryResult::PassToBackend) {
    if (query->downstream == nullptr) {
      return false;
    }

#ifdef HAVE_DNS_OVER_HTTPS
    if (dq.ids.du != nullptr) {
      dq.ids.du->downstream = query->downstream;
    }
#endif

    if (query->downstream->isTCPOnly() || !(dq.getProtocol().isUDP() || dq.getProtocol() == dnsdist::Protocol::DoH)) {
      query->downstream->passCrossProtocolQuery(std::move(query));
      return true;
    }

    auto queryID = dq.getHeader()->id;
    /* at this point 'du', if it is not nullptr, is owned by the DoHCrossProtocolQuery
       which will stop existing when we return, so we need to increment the reference count
    */
    return assignOutgoingUDPQueryToBackend(query->downstream, queryID, dq, std::move(query->query.d_buffer), ids.origDest);
  }
  else if (result == ProcessQueryResult::SendAnswer) {
    auto sender = query->getTCPQuerySender();
    if (!sender) {
      return false;
    }

    struct timeval now;
    gettimeofday(&now, nullptr);

    TCPResponse response(std::move(query->query.d_buffer), std::move(query->query.d_idstate), nullptr);
    response.d_async = true;
    response.d_selfGenerated = true;

    try {
      sender->handleResponse(now, std::move(response));
      return true;
    }
    catch (const std::exception& e) {
      vinfolog("Got exception while resuming cross-protocol self-answered query: %s", e.what());
      return false;
    }
  }
  else if (result == ProcessQueryResult::Asynchronous) {
    /* nope */
    errlog("processQueryAfterRules returned 'asynchronous' while trying to resume an already asynchronous query");
    return false;
  }

  return false;
}

bool suspendQuery(DNSQuestion& dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  if (!g_asyncHolder) {
    return false;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  struct timeval ttd = now;
  ttd.tv_sec += timeoutMs / 1000;
  ttd.tv_usec += (timeoutMs % 1000) * 1000;
  if (ttd.tv_usec >= 1000000) {
    ttd.tv_sec++;
    ttd.tv_usec -= 1000000;
  }

  vinfolog("Suspending asynchronous query %d at %d.%d until %d.%d", queryID, now.tv_sec, now.tv_usec, ttd.tv_sec, ttd.tv_usec);
  auto query = getInternalQueryFromDQ(dq);

  g_asyncHolder->push(asyncID, queryID, ttd, std::move(query));
  return true;
}

bool suspendResponse(DNSResponse& dr, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  if (!g_asyncHolder) {
    return false;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  struct timeval ttd = now;
  ttd.tv_sec += timeoutMs / 1000;
  ttd.tv_usec += (timeoutMs % 1000) * 1000;
  if (ttd.tv_usec >= 1000000) {
    ttd.tv_sec++;
    ttd.tv_usec -= 1000000;
  }

  vinfolog("Suspending asynchronous response %d at %d.%d until %d.%d", queryID, now.tv_sec, now.tv_usec, ttd.tv_sec, ttd.tv_usec);
  auto query = getInternalQueryFromDQ(dr);
  query->isResponse = true;
  query->downstream = dr.d_downstream;

  g_asyncHolder->push(asyncID, queryID, ttd, std::move(query));
  return true;
}

std::unique_ptr<AsynchronousHolder> g_asyncHolder;
}
