if get_option('ebpf').allowed()
  if cxx.check_header('linux/bpf.h') and cxx.get_define('SO_ATTACH_BPF', prefix: '#include "sys/socket.h"') != ''
     conf.set('HAVE_EBPF', true, description: 'eBPF')

     symbols = [
       'BPF_FUNC_get_prandom_u32',
     ]

     foreach symbol: symbols
       has = cxx.get_define(func, prefix: '#include <linux/bpf.h>')
       conf.set('HAVE_' + symbol.to_upper(), has, description: 'Have eBPF ' + symbol)
     endforeach

     summary('eBPF', true, bool_yn: true, section: 'eBPF')
  else
     summary('eBPF', false, bool_yn: true, section: 'eBPF')
  endif
endif
