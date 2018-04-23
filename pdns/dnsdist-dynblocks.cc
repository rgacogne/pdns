
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"

size_t g_dynBlockCleaningDelay{0};

void purgeExpiredDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG)
{
  NetmaskTree<DynBlock> fresh;
  const auto full = dynblockNMG.getCopy();
  bool modified = false;
  struct timespec now;
  gettime(&now);

  for(const auto& entry: full) {
    if (now < entry->second.until) {
      fresh.insert(entry->first).second = entry->second;
    }
    else {
      modified = true;
    }
  }

  if (modified) {
    dynblockNMG.setState(fresh);
  }
}

void purgeExpiredDynBlockSMTEntries(GlobalStateHolder<SuffixMatchTree<DynBlock>>& dynblockSMT)
{
  SuffixMatchTree<DynBlock> fresh;
  const auto full = dynblockSMT.getCopy();
  bool modified = false;
  struct timespec now;
  gettime(&now);

  full.visit([now, &fresh, &modified](const SuffixMatchTree<DynBlock>& node) {
    if (now < node.d_value.until) {
      fresh.add(node.d_value.domain, node.d_value);
    } else {
      modified = true;
    }
  });

  if (modified) {
    dynblockSMT.setState(fresh);
  }
}
