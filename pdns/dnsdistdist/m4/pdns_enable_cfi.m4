AC_DEFUN([PDNS_ENABLE_CFI], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable Control-Flow Integrity])
  AC_ARG_ENABLE([cfi],
    AS_HELP_STRING([--enable-cfi],
      [enable Control-Flow Integrity @<:@default=no@:>@]),
    [enable_cfi=$enableval],
    [enable_cfi=no]
  )
  AC_MSG_RESULT([$enable_cfi])

  AS_IF([test "x$enable_cfi" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=cfi -flto -fvisibility=hidden],
      [
        CFLAGS="-fsanitize=cfi -flto -fvisibility=hidden $CFLAGS"
        CXXFLAGS="-fsanitize=cfi -flto -fvisibility=hidden $CXXFLAGS"
        LDFLAGS="-fsanitize=cfi -flto -fvisibility=hidden $LDFLAGS"
      ],
      [AC_MSG_ERROR([Cannot enable Control-Flow Integrity])]
    )
  ])
])
