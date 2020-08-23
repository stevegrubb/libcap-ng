Summary: An alternate posix capabilities library
Name: libcap-ng
Version: 0.7.11
Release: 1
License: LGPLv2+
Group: System Environment/Libraries
URL: http://people.redhat.com/sgrubb/libcap-ng
Source0: http://people.redhat.com/sgrubb/libcap-ng/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: kernel-headers >= 2.6.11 
BuildRequires: libattr-devel

%description
Libcap-ng is a library that makes using posix capabilities easier

%package devel
Summary: Header files for libcap-ng library
License: LGPLv2+
Group: Development/Libraries
Requires: kernel-headers >= 2.6.11
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
The libcap-ng-devel package contains the files needed for developing
applications that need to use the libcap-ng library.

%package -n python2-libcap-ng
%{?python_provide:%python_provide python2-libcap-ng}
# Remove in future
Summary: Python2 bindings for libcap-ng library
License: LGPLv2+
Group: Development/Libraries
BuildRequires: python2-devel swig
Requires: %{name} = %{version}-%{release}
Provides: %{name}-python = %{version}-%{release}
Provides: %{name}-python%{?_isa} = %{version}-%{release}
Obsoletes: %{name}-python < %{version}-%{release}

%description python2-libcap-ng
The python2-libcap-ng package contains the bindings so that libcap-ng
and can be used by python2 applications.

%package python3
Summary: Python3 bindings for libcap-ng library
License: LGPLv2+
Group: Development/Libraries
BuildRequires: python3-devel swig
Requires: %{name} = %{version}-%{release}

%description python3
The libcap-ng-python3 package contains the bindings so that libcap-ng
and can be used by python3 applications.

%package utils
Summary: Utilities for analyzing and setting file capabilities
License: GPLv2+
Group: Development/Libraries

%description utils
The libcap-ng-utils package contains applications to analyze the
posix capabilities of all the program running on a system. It also
lets you set the file system based capabilities.

%prep
%setup -q

%build
%configure --libdir=/%{_lib} --with-python --with-python3
make %{?_smp_mflags}

%install
make DESTDIR="${RPM_BUILD_ROOT}" INSTALL='install -p' install

# Move the symlink
rm -f $RPM_BUILD_ROOT/%{_lib}/%{name}.so
mkdir -p $RPM_BUILD_ROOT%{_libdir}
VLIBNAME=$(ls $RPM_BUILD_ROOT/%{_lib}/%{name}.so.*.*.*)
LIBNAME=$(basename $VLIBNAME)
ln -s ../../%{_lib}/$LIBNAME $RPM_BUILD_ROOT%{_libdir}/%{name}.so

# Move the pkgconfig file
mv $RPM_BUILD_ROOT/%{_lib}/pkgconfig $RPM_BUILD_ROOT%{_libdir}

# Remove a couple things so they don't get picked up
rm -f $RPM_BUILD_ROOT/%{_lib}/libcap-ng.la
rm -f $RPM_BUILD_ROOT/%{_lib}/libcap-ng.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_capng.a
rm -f $RPM_BUILD_ROOT/%{_libdir}/python?.?/site-packages/_capng.la

%check
make check

%ldconfig_scriptlets

%files
%defattr(-,root,root,-)
%doc COPYING.LIB
/%{_lib}/libcap-ng.so.*

%files devel
%defattr(-,root,root,-)
%attr(0644,root,root) %{_mandir}/man3/*
%attr(0644,root,root) %{_includedir}/cap-ng.h
%{_libdir}/libcap-ng.so
%attr(0644,root,root) %{_datadir}/aclocal/cap-ng.m4
%{_libdir}/pkgconfig/libcap-ng.pc

%files -n python2-libcap-ng
%defattr(-,root,root,-)
%attr(755,root,root) %{python2_sitearch}/_capng.so
%{python2_sitearch}/capng.py*

%files python3
%defattr(-,root,root,-)
%attr(755,root,root) %{python3_sitearch}/*
%{python3_sitearch}/capng.py*

%files utils
%defattr(-,root,root,-)
%doc COPYING
%attr(0755,root,root) %{_bindir}/*
%attr(0644,root,root) %{_mandir}/man8/*

%changelog
* Sun Aug 23 2020 Steve Grubb <sgrubb@redhat.com> 0.7.11-1
- New upstream release

