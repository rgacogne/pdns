
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"

void purgeExpiredDynBlockNMGEntries(GlobalStateHolder<NetmaskTree<DynBlock>>& dynblockNMG)
{
  NetmaskTree<DynBlock> fresh;
  const auto full = dynblockNMG.getCopy();
  struct timespec now;
  gettime(&now);

  for(const auto& entry: full) {
    if (now < entry->second.until) {
      fresh.insert(entry->first).second = entry->second;
    }
  }

  dynblockNMG.setState(fresh);
}

void purgeExpiredDynBlockSMTEntries(GlobalStateHolder<SuffixMatchTree<DynBlock>>& dynblockSMT)
{
  SuffixMatchTree<DynBlock> fresh;
  const auto full = dynblockSMT.getCopy();
  struct timespec now;
  gettime(&now);

  full.visit([now, &fresh](const SuffixMatchTree<DynBlock>& node) {
    if (now < node.d_value.until) {
      fresh.add(node.d_value.domain, node.d_value);
    }
  });

  dynblockSMT.setState(fresh);
}
