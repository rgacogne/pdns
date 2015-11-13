AC_DEFUN([PDNS_CHECK_HDR_HISTOGRAM], [
  AC_MSG_CHECKING([whether we will be linking in hdr histogram])
  AC_ARG_ENABLE([hdr_histogram],
    AS_HELP_STRING([--enable-hdr-histogram],[use hdr histogram @<:@default=no@:>@]),
    [enable_hdr_histogram=$enableval],
    [enable_hdr_histogram=no],
  )
  AC_MSG_RESULT([$enable_hdr_histogram])

  AM_CONDITIONAL([HDR_HISTOGRAM], [test "x$enable_hdr_histogram" != "xno"])

  AM_COND_IF([HDR_HISTOGRAM], [
    AC_DEFINE([HAVE_HDR_HISTOGRAM], [1], [Define to 1 if you have hdr histogram])
  ])
])
