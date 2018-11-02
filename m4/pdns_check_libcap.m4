AC_DEFUN([PDNS_CHECK_LIBCAP], [
  AC_MSG_CHECKING([whether we will be linking in libcap])
  HAVE_LIBCAPS=0
  AC_ARG_ENABLE([libcap],
    AS_HELP_STRING([--enable-libcap],[use libcap @<:@default=auto@:>@]),
    [enable_libcap=$enableval],
    [enable_libcap=auto],
  )
  AC_MSG_RESULT([$enable_libcap])

  AS_IF([test "x$enable_libcap" != "xno"], [
    AS_IF([test "x$enable_libcap" = "xyes" -o "x$enable_libcap" = "xauto"], [
      PKG_CHECK_MODULES([LIBCAP], [libcap] , [
        [HAVE_LIBCAP=1]
        AC_DEFINE([HAVE_LIBCAP], [1], [Define to 1 if you have libcap])
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_LIBCAP], [test "x$LIBCAP_LIBS" != "x"])
  AS_IF([test "x$enable_libcap" = "xyes"], [
    AS_IF([test x"$LIBCAP_LIBS" = "x"], [
      AC_MSG_ERROR([libcap requested but libraries were not found])
    ])
  ])
])
