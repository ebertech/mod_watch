Summary:  mod_watch - Bandwidth accounting for Apache
Name:     mod_watch
Group:    System Environment/Daemons
Version:  4.3
Release:  2%{?dist}
License:  GPL
URL:      http://www.snert.com/
Packager: Ryan McKern <ryan.mckern@mathworks.com>

BuildRequires:  apr
BuildRequires:  apr-util
Requires:       httpd

Source0:  %{name}-%{version}_apache22_mod.tar.gz
Source1:  mod_watch.conf

Patch1:   mod_watch-mutex.patch
Patch2:   mod_watch-segfault.patch
Patch3:   mod_watch-shm.patch

BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
mod_watch is a bandwidth accounting module for Apache virtualhosts

%prep

[ -n %{buildroot} ] && rm -rf %{buildroot}

[ -d %{_builddir}/%{name}-%{version} ] && rm -rf %{_builddir}/%{name}-%{version}

%setup -q -n %{name}-%{version}

%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
%{__make} %{?_smp_mflags} -f Makefile.dso build APXS="%{_sbindir}/apxs"

# build the .so
%{_sbindir}/apxs -c *.lo

%install

## make the "install" dir
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/httpd/modules
mkdir -p %{buildroot}%{_localstatedir}/lib/mod_watch
mkdir -p %{buildroot}%{_localstatedir}/lib/mod_watch/ip
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d

cp -f .libs/mod_watch.so %{buildroot}%{_libdir}/httpd/modules
cp -f apache2mrtg.pl %{buildroot}%{_bindir}
cp -f mod_watch.pl %{buildroot}%{_bindir}
install -m 640 %{SOURCE1} %{buildroot}%{_sysconfdir}/httpd/conf.d/watch.conf

%clean
[ -n "%{buildroot}" -a "%{buildroot}" != / ] && rm -rf %{buildroot}
[ -d %{_builddir}/%{name}-%{version} ] && rm -rf %{_builddir}/%{name}-%{version}

%pre

%postun

[ -d %{_localstatedir}/%{name} ] && 
  rm -rf %{_localstatedir}/%{name} || :

%post

%files
%defattr(-,root,root)

%attr(0755,root,root) %{_bindir}/mod_watch.pl
%attr(0755,root,root) %{_bindir}/apache2mrtg.pl
%attr(0755,root,root) %{_libdir}/httpd/modules/mod_watch.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/watch.conf
%attr(0640,root,root) %{_sysconfdir}/httpd/conf.d/watch.conf

%attr(0750,root,apache) %dir %{_localstatedir}/lib/mod_watch
%attr(0750,root,apache) %dir %{_localstatedir}/lib/mod_watch/ip

%changelog
* Wed May 4 2011 Ryan McKern <ryan@orangefort.com>
- Included the mutex patch to allow changing the setting for the shared memory lock
- Included the segfault patch from Interworx
- Included the SHM patch to address issues with error logging
