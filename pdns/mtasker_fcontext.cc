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
#include "mtasker_context.hh"
#include <exception>
#include <cassert>
#include <type_traits>
#include <boost/version.hpp>
#if BOOST_VERSION < 106100
#include <boost/config.hpp>
#include <boost/cstdint.hpp>

#include <boost/context/detail/config.hpp>

#ifdef BOOST_HAS_ABI_HEADERS
# include BOOST_ABI_PREFIX
#endif

// x86_64
// test x86_64 before i386 because icc might
// define __i686__ for x86_64 too
#if defined(__x86_64__) || defined(__x86_64) \
  || defined(__amd64__) || defined(__amd64) \
  || defined(_M_X64) || defined(_M_AMD64)
# if defined(BOOST_WINDOWS)
#  include <boost/context/detail/fcontext_x86_64_win.hpp>
# else
#  include <boost/context/detail/fcontext_x86_64.hpp>
# endif
// i386
#elif defined(i386) || defined(__i386__) || defined(__i386) \
  || defined(__i486__) || defined(__i586__) || defined(__i686__) \
  || defined(__X86__) || defined(_X86_) || defined(__THW_INTEL__) \
  || defined(__I86__) || defined(__INTEL__) || defined(__IA32__) \
  || defined(_M_IX86) || defined(_I86_)
# if defined(BOOST_WINDOWS)
#  include <boost/context/detail/fcontext_i386_win.hpp>
# else
#  include <boost/context/detail/fcontext_i386.hpp>
# endif
// arm
#elif defined(__arm__) || defined(__thumb__) || defined(__TARGET_ARCH_ARM) \
  || defined(__TARGET_ARCH_THUMB) || defined(_ARM) || defined(_M_ARM)
# include <boost/context/detail/fcontext_arm.hpp>
// mips
#elif (defined(__mips) && __mips == 1) || defined(_MIPS_ISA_MIPS1) \
  || defined(_R3000)
# include <boost/context/detail/fcontext_mips.hpp>
// powerpc
#elif defined(__powerpc) || defined(__powerpc__) || defined(__ppc) \
  || defined(__ppc__) || defined(_ARCH_PPC) || defined(__POWERPC__) \
  || defined(__PPCGECKO__) || defined(__PPCBROADWAY) || defined(_XENON)
# include <boost/context/detail/fcontext_ppc.hpp>
#elif defined(__sparc__) || defined(__sparc)
// sparc or sparc64
# include <boost/context/detail/fcontext_sparc.hpp>
#else
# error "platform not supported"
#endif
namespace boost {
namespace context {

extern "C" BOOST_CONTEXT_DECL
intptr_t BOOST_CONTEXT_CALLDECL jump_fcontext( fcontext_t * ofc, fcontext_t const* nfc, intptr_t vp, bool preserve_fpu = true);
extern "C" BOOST_CONTEXT_DECL
fcontext_t * BOOST_CONTEXT_CALLDECL make_fcontext( void * sp, std::size_t size, void (* fn)( intptr_t) );

}}

#ifdef BOOST_HAS_ABI_HEADERS
# include BOOST_ABI_SUFFIX
#endif

using boost::context::make_fcontext;
#else
#include <boost/context/detail/fcontext.hpp>
using boost::context::detail::make_fcontext;
#endif /* BOOST_VERSION < 106100 */


#if BOOST_VERSION < 105600
/* Note: This typedef means functions taking fcontext_t*, like jump_fcontext(),
 * now require a reinterpret_cast rather than a static_cast, since we're
 * casting from pdns_context_t->uc_mcontext, which is void**, to
 * some_opaque_struct**. In later versions fcontext_t is already void*. So if
 * you remove this, then fix the ugly.
 */
using fcontext_t = boost::context::fcontext_t*;

/* Emulate the >= 1.56 API for Boost 1.52 through 1.55 */
static inline intptr_t
jump_fcontext (fcontext_t* const ofc, fcontext_t const nfc, 
               intptr_t const arg) {
    /* If the fcontext_t is preallocated then use it, otherwise allocate one
     * on the stack ('self') and stash a pointer away in *ofc so the returning
     * MThread can access it. This is safe because we're suspended, so the
     * context object always outlives the jump.
     */
    if (*ofc) {
        return boost::context::jump_fcontext (*ofc, nfc, arg);
    } else {
        boost::context::fcontext_t self;
        *ofc = &self;
        auto ret = boost::context::jump_fcontext (*ofc, nfc, arg);
        *ofc = nullptr;
        return ret;
    }
}
#else

#if BOOST_VERSION < 106100
using boost::context::fcontext_t;
using boost::context::jump_fcontext;
#else
using boost::context::detail::fcontext_t;
using boost::context::detail::jump_fcontext;
using boost::context::detail::transfer_t;
#endif /* BOOST_VERSION < 106100 */

static_assert (std::is_pointer<fcontext_t>::value,
               "Boost Context has changed the fcontext_t type again :-(");
#endif

/* Boost context only provides a means of passing a single argument across a
 * jump. args_t simply provides a way to pass more by reference.
 */
struct args_t {
#if BOOST_VERSION < 106100
    fcontext_t prev_ctx = nullptr;
#endif
    pdns_ucontext_t* self = nullptr;
    boost::function<void(void)>* work = nullptr;
};

extern "C" {
static
void
#if BOOST_VERSION < 106100
threadWrapper (intptr_t const xargs) {
#else
threadWrapper (transfer_t const t) {
#endif
    /* Access the args passed from pdns_makecontext, and copy them directly from
     * the calling stack on to ours (we're now using the MThreads stack).
     * This saves heap allocating an args object, at the cost of an extra
     * context switch to fashion this constructor-like init phase. The work
     * function object is still only moved after we're (re)started, so may
     * still be set or changed after a call to pdns_makecontext. This matches
     * the behaviour of the System V implementation, which can inherently only
     * be passed ints and pointers.
     */
#if BOOST_VERSION < 106100
    auto args = reinterpret_cast<args_t*>(xargs);
#else
    auto args = reinterpret_cast<args_t*>(t.data);
#endif
    auto ctx = args->self;
    auto work = args->work;
    /* we switch back to pdns_makecontext() */
#if BOOST_VERSION < 106100
    jump_fcontext (reinterpret_cast<fcontext_t*>(&ctx->uc_mcontext),
                   static_cast<fcontext_t>(args->prev_ctx), 0);
#else
    transfer_t res = jump_fcontext (t.fctx, 0);
    /* we got switched back from pdns_swapcontext() */
    if (res.data) {
      /* if res.data is not a nullptr, it holds a pointer to the context
         we just switched from, and we need to fill it to be able to
         switch back to it later. */
      fcontext_t* ptr = static_cast<fcontext_t*>(res.data);
      *ptr = res.fctx;
    }
#endif
    args = nullptr;

    try {
        auto start = std::move (*work);
        start();
    } catch (...) {
        ctx->exception = std::current_exception();
    }

    /* Emulate the System V uc_link feature. */
    auto const next_ctx = ctx->uc_link->uc_mcontext;
#if BOOST_VERSION < 106100
    jump_fcontext (reinterpret_cast<fcontext_t*>(&ctx->uc_mcontext),
                   static_cast<fcontext_t>(next_ctx),
                   static_cast<bool>(ctx->exception));
#else
    jump_fcontext (static_cast<fcontext_t>(next_ctx), 0);
#endif

#ifdef NDEBUG
    __builtin_unreachable();
#endif
}
}

pdns_ucontext_t::pdns_ucontext_t
(): uc_mcontext(nullptr), uc_link(nullptr) {
}

pdns_ucontext_t::~pdns_ucontext_t
() {
    /* There's nothing to delete here since fcontext doesn't require anything
     * to be heap allocated.
     */
}

void
pdns_swapcontext
(pdns_ucontext_t& __restrict octx, pdns_ucontext_t const& __restrict ctx) {
  /* we either switch back to threadwrapper() if it's the first time,
     or we switch back to pdns_swapcontext(),
     in both case we will be returning from a call to jump_fcontext(). */
#if BOOST_VERSION < 106100
    if (jump_fcontext (reinterpret_cast<fcontext_t*>(&octx.uc_mcontext),
                       static_cast<fcontext_t>(ctx.uc_mcontext), 0)) {
        std::rethrow_exception (ctx.exception);
    }
#else
  transfer_t res = jump_fcontext (static_cast<fcontext_t>(ctx.uc_mcontext), &octx.uc_mcontext);
  if (res.data) {
    /* if res.data is not a nullptr, it holds a pointer to the context
       we just switched from, and we need to fill it to be able to
       switch back to it later. */
    fcontext_t* ptr = static_cast<fcontext_t*>(res.data);
    *ptr = res.fctx;
  }
  if (ctx.exception) {
    std::rethrow_exception (ctx.exception);
  }
#endif
}

void
pdns_makecontext
(pdns_ucontext_t& ctx, boost::function<void(void)>& start) {
    assert (ctx.uc_link);
    assert (ctx.uc_stack.size() >= 8192);
    assert (!ctx.uc_mcontext);
    ctx.uc_mcontext = make_fcontext (&ctx.uc_stack[ctx.uc_stack.size()],
                                     ctx.uc_stack.size(), &threadWrapper);
    args_t args;
    args.self = &ctx;
    args.work = &start;
    /* jumping to threadwrapper */
#if BOOST_VERSION < 106100
    jump_fcontext (reinterpret_cast<fcontext_t*>(&args.prev_ctx),
                   static_cast<fcontext_t>(ctx.uc_mcontext),
                   reinterpret_cast<intptr_t>(&args));
#else
    transfer_t res = jump_fcontext (static_cast<fcontext_t>(ctx.uc_mcontext),
                                    &args);
    /* back from threadwrapper, updating the context */
    ctx.uc_mcontext = res.fctx;
#endif
}
