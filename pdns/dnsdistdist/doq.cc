
#include "doq.hh"
#include "dnsdist.hh"

std::vector<std::shared_ptr<DOQFrontend>> g_doqlocals;

static handleDoQMessage(int fd, FDMultiplexer::funcparam_t& param)
{
  
}

void doqThread(ClientState* cs)
{
  setThreadName("dnsdist/doq");

  setNonBlocking(cs->udpFD);

  auto mplexer = std::shared_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
  mplexer->addReadFD(cs->udpFD, handleDoQMessage, cs);
  struct timeval now;

  for (;;) {
    mplexer->run(&now);
  }
}
