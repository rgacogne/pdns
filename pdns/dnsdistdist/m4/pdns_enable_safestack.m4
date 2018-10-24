AC_DEFUN([PDNS_ENABLE_SAFESTACK], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable SafeStack])
  AC_ARG_ENABLE([safestack],
    AS_HELP_STRING([--enable-safestack],
      [enable SafeStack @<:@default=no@:>@]),
    [enable_safestack=$enableval],
    [enable_safestack=no]
  )
  AC_MSG_RESULT([$enable_safestack])

  AS_IF([test "x$enable_safestack" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=safestack],
      [
        CFLAGS="-fsanitize=safestack $CFLAGS"
        CXXFLAGS="-fsanitize=safestack $CXXFLAGS"
        LDFLAGS="-fsanitize=safestack $LDFLAGS"
      ],
      [AC_MSG_ERROR([Cannot enable SafeStack])]
    )
  ])
])
