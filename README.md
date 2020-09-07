# libcap-ng
The libcap-ng library should make programming with posix capabilities
easier. The library has some utilities to help you analyse a system
for apps that may have too much privileges. It also comes with python
bindings. However, printing capabilities from python does not work. But
you can still manipulate capabilities, though.

NOTE: to distributions. There is a "make check" target. It only works
if the headers match the kernel. IOW, if you have a chroot build system
that is using a much older kernel, the macros in the kernel header files
will do the wrong thing when the capng_init function probes the kernel
and decides we are doing v1 rather than v3 protocol. If that is your case,
just don't do the "make check" as part of the build process.

Report any bugs in this package to:
https://github.com/stevegrubb/libcap-ng/issue

Additional information can be found at:
	http://people.redhat.com/sgrubb/libcap-ng
