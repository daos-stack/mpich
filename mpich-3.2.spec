%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}

Summary:	A high-performance implementation of MPI
Name:		mpich
Version:	3.2
Release:	2%{?dist}
License:	MIT
Group:		Development/Libraries
URL:		http://www.mpich.org

Source0:	http://www.mpich.org/static/downloads/%{version}/%{name}-%{version}.tar.gz
Source1:	mpich.macros.in
Source2:	mpich.module.in
Patch1:		https://trac.mpich.org/projects/mpich/raw-attachment/ticket/2299/0001-pm-remshell-include-MPL-when-linking.patch
Patch2:		0002-pm-gforker-include-MPL-when-linking.patch
Patch3:		0003-soften-version-check.patch
Patch4:		0001-hydra-improve-localhost-detection.patch
Patch5:		0001-Revert-require-automake-1.15.patch
Patch6:		0002-Revert-require-libtool-2.4.3.patch
Patch7:		0003-unbundle-YAML-Tiny.patch
Patch8:		0004-unbundle-hwloc-from-hydra.patch

# Source100 derived from
# Source100:	http://www.mpich.org/static/downloads/3.0.4/mpich-3.0.4.tar.gz
# by
# rm -r src/mpid/pamid
# vi src/mpid/Makefile*
#  and remove references to pamid
# rm -r src/mpid/ch3/channels/nemesis/netmod/scif
# vi src/src/mpid/ch3/channels/nemesis/netmod/Makefile*
#  and remove references to scif
# rm -r src/pm/hydra/tools/topo/hwloc/hwloc
# vi src/pm/hydra/tools/topo/hwloc/Makefile.mk
#  and remove references to hwloc
# rm `find * -name 'Makefile.in' -print | grep -v doc/ | grep -v src/mpi/romio/mpi2-other/`
# rm -r contrib www
# rm src/mpi/romio/test/external32.c
# rm `find * -name ar-lib -o -name compile -o -name config.guess -o -name config.sub -o -name depcomp -o -name missing -o -name configure -o -name .state-cache -o -name aclocal.mp -o -name libtool.m4`
# rm README.envvar maint/createcoverage maint/getcoverage src/include/mpichconf.h.in src/include/mpich_param_vals.h src/pm/hydra/include/hydra_config.h.in src/util/logging/common/state_names.h src/util/param/param_vals.c subsys_include.m4
#  more extensive changes need to actually build are included in the mpich-3.0.4-rh.patch file
Source100:	mpich-3.0.4-rh.tar.gz
Patch100:	mpich-3.0.4-rh.patch

BuildRequires:	libXt-devel, bison, flex, libuuid-devel
BuildRequires:	gcc-c++ gcc-gfortran
BuildRequires:  hwloc-devel >= 1.5
BuildRequires:	perl, python, perl-Digest-MD5, perl-YAML-Tiny
BuildRequires:	automake autoconf libtool gettext
%ifnarch s390
BuildRequires:	valgrind-devel
%endif

%global common_desc MPICH is a high-performance and widely portable implementation of the Message\
Passing Interface (MPI) standard (MPI-1, MPI-2 and MPI-3). The goals of MPICH\
are: (1) to provide an MPI implementation that efficiently supports different\
computation and communication platforms including commodity clusters (desktop\
systems, shared-memory systems, multicore architectures), high-speed networks\
(10 Gigabit Ethernet, InfiniBand, Myrinet, Quadrics) and proprietary high-end\
computing systems (Blue Gene, Cray) and (2) to enable cutting-edge research in\
MPI through an easy-to-extend modular framework for other derived\
implementations.\
\
The mpich binaries in this RPM packages were configured to use the default\
process manager (Hydra) using the default device (ch3). The ch3 device\
was configured with support for the nemesis channel that allows for\
shared-memory and TCP/IP sockets based communication.

%description
%{common_desc}

%package 3.2
Summary:	A high-performance implementation of MPI
Group:		Development/Libraries
Obsoletes:	mpich2 < 1.5-4
Obsoletes:	mpich-libs < 1.1.1
Obsoletes:	mpich-mpd < 1.4.1
Obsoletes:	mpich < 3.0.4-9
Provides:	mpi
Requires:	environment-modules

%description 3.2
%{common_desc}

%package 3.2-autoload
Summary:	Load mpich 3.2 automatically into profile
Group:		System Environment/Base
Requires:	mpich-3.2 = %{version}-%{release}

%description 3.2-autoload
This package contains profile files that make mpich 3.2 automatically loaded.

%package 3.2-devel
Summary:	Development files for mpich-3.2
Group:		Development/Libraries
Provides:	mpi-devel
Obsoletes:	mpich-devel < 3.0.4-9
Requires:	mpich-3.2 = %{version}-%{release}
Requires:	pkgconfig
Requires:	gcc-gfortran

%description 3.2-devel
Contains development headers and libraries for mpich 3.2.

%package 3.2-doc
Summary:	Documentations and examples for mpich 3.2
Group:		Documentation
BuildArch:	noarch
Obsoletes:	mpich-doc < 3.0.4-9
Requires:	mpich-3.2-devel = %{version}-%{release}

%description 3.2-doc
Contains documentations, examples and manpages for mpich 3.2.

%package 3.0
Summary:	MPICH 3.0.x implementation of MPI
Group:		Development/Libraries
Version:	3.0.4
Release:	10%{?dist}
Obsoletes:	mpich2 < 1.5-4
Obsoletes:	mpich-libs < 1.1.1
Obsoletes:	mpich-mpd < 1.4.1
Obsoletes:	mpich < 3.0.4-9
Provides:	mpi
Provides:	mpich = %{version}-%{release}
Provides:	mpich%{?_isa} = %{version}-%{release}
Requires:	environment-modules

%description 3.0
%{common_desc}

This package provides compatibility for applications compiled with MPICH 3.0.4.

%package 3.0-autoload
Summary:	Load mpich 3.0 automatically into profile
Group:		System Environment/Base
Version:	%{version}
Release:	%{release}
Obsoletes:	mpich-autoload < 3.0.4-9
Provides:	mpich-autoload = %{version}-%{release}
Requires:	mpich-3.0 = %{version}-%{release}

%description 3.0-autoload
This package contains profile files that make mpich 3.0 automatically loaded.

%package 3.0-devel
Summary:	Development files for mpich-3.0
Group:		Development/Libraries
Version:	%{version}
Release:	%{release}
Provides:	mpi-devel
Obsoletes:	mpich-devel < 3.0.4-9
Provides:	mpich-devel = %{version}-%{release}
Requires:	mpich-3.0 = %{version}-%{release}
Requires:	pkgconfig
Requires:	gcc-gfortran

%description 3.0-devel
Contains development headers and libraries for mpich 3.0.

%package 3.0-doc
Summary:	Documentations and examples for mpich 3.0
Group:		Documentation
Version:	%{version}
Release:	%{release}
BuildArch:	noarch
Obsoletes:	mpich-doc < 3.0.4-9
Provides:	mpich-doc = %{version}-%{release}
Requires:	mpich-3.0-devel = %{version}-%{release}

%description 3.0-doc
Contains documentations, examples and manpages for mpich 3.0.

# We only compile with gcc, but other people may want other compilers.
# Set the compiler here.
%{!?opt_cc: %global opt_cc gcc}
%{!?opt_fc: %global opt_fc gfortran}
%{!?opt_f77: %global opt_f77 gfortran}
# Optional CFLAGS to use with the specific compiler...gcc doesn't need any,
# so uncomment and undefine to NOT use
%{!?opt_cc_cflags: %global opt_cc_cflags %{optflags}}
%{!?opt_fc_fflags: %global opt_fc_fflags %{optflags}}
#%{!?opt_fc_fflags: %global opt_fc_fflags %{optflags} -I%{_fmoddir}}
%{!?opt_f77_fflags: %global opt_f77_fflags %{optflags}}

%prep
%setup -q -b 100
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1

  # bundled knem module
  rm -r contrib/
  # bundled YAML::Tiny
  rm -r maint/local_perl/
  # bundled hwloc
  rm -r src/pm/hydra/tools/topo/hwloc/hwloc/
  # HTML manpages
  rm -r www/

  ./autogen.sh
cd ..

cd mpich-3.0.4
%patch100 -p1 -b .rh

  ./autogen.sh
  cd src/pm/hydra && ./autogen.sh && cd ../../..
cd ..

%build
cd ..

%ifarch s390
%global m_option -m31
%else
%global m_option -m%{__isa_bits}
%endif

%ifarch %{arm} aarch64
%global m_option ""
%endif

%global selected_channels ch3:nemesis

%ifarch %{ix86} x86_64 s390 %{arm} aarch64
%global XFLAGS -fPIC
%endif

%global variant mpich-3.2
%global libname %{variant}
%global namearch %{variant}-%{_arch}

cd mpich-3.2
%configure	\
	--enable-sharedlibs=gcc					\
	--enable-shared						\
	--enable-static=no                                      \
	--enable-lib-depend					\
	--disable-rpath						\
	--disable-silent-rules					\
	--enable-fc						\
	--with-device=%{selected_channels}			\
	--with-pm=hydra:gforker					\
	--sysconfdir=%{_sysconfdir}/%{namearch}			\
	--includedir=%{_includedir}/%{namearch}			\
	--bindir=%{_libdir}/%{libname}/bin			\
	--libdir=%{_libdir}/%{libname}/lib			\
	--datadir=%{_datadir}/%{libname}			\
	--mandir=%{_mandir}/%{libname}				\
	--docdir=%{_docdir}/%{libname}				\
	--with-hwloc-prefix=system				\
	FC=%{opt_fc}						\
	F77=%{opt_f77}						\
	CFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	CXXFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	FCFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	FFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	LDFLAGS='-Wl,-z,noexecstack'				\
	MPICH2LIB_CFLAGS="%{?opt_cc_cflags}"			\
	MPICH2LIB_CXXFLAGS="%{optflags}"			\
	MPICH2LIB_FCFLAGS="%{?opt_fc_fflags}"			\
	MPICH2LIB_FFLAGS="%{?opt_f77_fflags}"
#	MPICH2LIB_LDFLAGS='-Wl,-z,noexecstack'			\
#	MPICH2_MPICC_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPICXX_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPIFC_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPIF77_FLAGS="%{m_option} -O2 %{?XFLAGS}"
#	--with-openpa-prefix=embedded				\

#	FCFLAGS="%{?opt_fc_fflags} -I%{_fmoddir}/%{name} %{?XFLAGS}"	\

# Remove rpath
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags} V=1
cd ..


%ifarch s390
%global m_option -m31
%else
%global m_option -m%{__isa_bits}
%endif

%ifarch %{arm} aarch64
%global m_option ""
%endif

%ifarch %{ix86} x86_64
%global selected_channels ch3:nemesis
%else
%global selected_channels ch3:sock
%endif

%ifarch %{ix86} x86_64 s390 %{arm}
%global XFLAGS -fPIC
%endif

%global variant mpich
%global libname %{variant}
%global namearch %{variant}-%{_arch}

cd mpich-3.0.4
%configure	\
	--enable-sharedlibs=gcc					\
	--enable-shared						\
	--enable-lib-depend					\
	--disable-rpath						\
	--enable-fc						\
	--with-device=%{selected_channels}			\
	--with-pm=hydra:gforker					\
	--sysconfdir=%{_sysconfdir}/%{namearch}			\
	--includedir=%{_includedir}/%{namearch}			\
	--bindir=%{_libdir}/%{libname}/bin			\
	--libdir=%{_libdir}/%{libname}/lib			\
	--datadir=%{_datadir}/%{libname}			\
	--mandir=%{_mandir}/%{libname}				\
	--docdir=%{_docdir}/%{libname}				\
	--with-hwloc-prefix=system				\
	FC=%{opt_fc}						\
	F77=%{opt_f77}						\
	CFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	CXXFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	FCFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	FFLAGS="%{m_option} %{optflags} %{?XFLAGS}"		\
	LDFLAGS='-Wl,-z,noexecstack'				\
	MPICH2LIB_CFLAGS="%{?opt_cc_cflags}"			\
	MPICH2LIB_CXXFLAGS="%{optflags}"			\
	MPICH2LIB_FCFLAGS="%{?opt_fc_fflags}"			\
	MPICH2LIB_FFLAGS="%{?opt_f77_fflags}"
#	MPICH2LIB_LDFLAGS='-Wl,-z,noexecstack'			\
#	MPICH2_MPICC_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPICXX_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPIFC_FLAGS="%{m_option} -O2 %{?XFLAGS}"	\
#	MPICH2_MPIF77_FLAGS="%{m_option} -O2 %{?XFLAGS}"
#	--with-openpa-prefix=embedded				\

#	FCFLAGS="%{?opt_fc_fflags} -I%{_fmoddir}/%{name} %{?XFLAGS}"	\
#make %{?_smp_mflags} doesn't work
make V=1
cd ..

%install
cd ..

finish_install() {
	local VARIANT="$1"
	local LIBNAME="$VARIANT"
	local NAMEARCH="$VARIANT-%{_arch}"

	find %{buildroot}%{_libdir}/$LIBNAME/lib -name \*.la -delete
	mkdir -p %{buildroot}/%{_fmoddir}/$NAMEARCH
	mkdir -p %{buildroot}%{python_sitearch}/$LIBNAME

	# Make the environment-modules file
	mkdir -p %{buildroot}%{_sysconfdir}/modulefiles/mpi
	sed "s#@LIBDIR@#%{_libdir}/$LIBNAME#g;
	     s#@ETCDIR@#%{_sysconfdir}/$NAMEARCH#g;
	     s#@FMODDIR@#%{_fmoddir}/$NAMEARCH#g;
	     s#@INCDIR@#%{_includedir}/$NAMEARCH#g;
	     s#@MANDIR@#%{_mandir}/$LIBNAME#g;
	     s#@PYSITEARCH@#%{python_sitearch}/$LIBNAME#g;
	     s#@COMPILER@#$NAMEARCH#g;
	     s#@SUFFIX@#_$LIBNAME#g" \
		< %SOURCE2 \
		> %{buildroot}%{_sysconfdir}/modulefiles/mpi/$NAMEARCH

	# Make the profile script for autoload
	mkdir -p %{buildroot}%{_sysconfdir}/profile.d
	cat << EOF > %{buildroot}%{_sysconfdir}/profile.d/$NAMEARCH.sh
# Load mpich environment module
module load mpi/$NAMEARCH
EOF
	cp -p %{buildroot}%{_sysconfdir}/profile.d/$NAMEARCH.{sh,csh}

	# Make the rpm macro file
	mkdir -p %{buildroot}/%{_sysconfdir}/rpm
	# do not expand _arch
	sed "s#@MACRONAME@#${LIBNAME//[-.]/_}#g;
	     s#@MODULENAME@#$VARIANT-%%{_arch}#" \
		< %SOURCE1 \
		> %{buildroot}/%{_sysconfdir}/rpm/macros.$LIBNAME
}

cd mpich-3.2
%make_install
cd ..
finish_install mpich-3.2

cd mpich-3.0.4
%make_install
cd ..
finish_install mpich
rm -f %{buildroot}%{_libdir}/mpich/lib/lib{*mpich*,opa,mpl}.a
ln -s mpich-%{_arch} %{buildroot}%{_sysconfdir}/modulefiles/mpi/mpich-3.0-%{_arch}
ln -s mpich-%{_arch} %{buildroot}%{_sysconfdir}/mpich-3.0-%{_arch}
# Silence rpmlint
sed -i '/^#! \//,1 d' %{buildroot}%{_sysconfdir}/mpich-%{_arch}/mpi*.conf

%global variant mpich-3.2
%global libname %{variant}
%global namearch %{variant}-%{_arch}

%files 3.2
%defattr(-,root,root,-)
%doc CHANGES COPYRIGHT README RELEASE_NOTES
%dir %{_libdir}/%{libname}
%dir %{_libdir}/%{libname}/lib
%dir %{_libdir}/%{libname}/bin
%{_libdir}/%{libname}/lib/*.so.*
%{_libdir}/%{libname}/bin/hydra*
%{_libdir}/%{libname}/bin/mpichversion
%{_libdir}/%{libname}/bin/mpiexec*
%{_libdir}/%{libname}/bin/mpirun
%{_libdir}/%{libname}/bin/mpivars
%dir %{python_sitearch}/%{libname}
%dir %{_fmoddir}/%{namearch}
%{_libdir}/%{libname}/bin/parkill
%dir %{_mandir}/%{libname}
%dir %{_mandir}/%{libname}/man1
%{_mandir}/%{libname}/man1/mpiexec*
%{_mandir}/%{libname}/man1/hydra*
%dir %{_sysconfdir}/modulefiles/mpi
%{_sysconfdir}/modulefiles/mpi/%{namearch}

%files 3.2-autoload
%defattr(-,root,root,-)
%{_sysconfdir}/profile.d/%{namearch}.*

%files 3.2-devel
%defattr(-,root,root,-)
%{_libdir}/%{libname}/bin/mpicc
%{_libdir}/%{libname}/bin/mpicxx
%{_libdir}/%{libname}/bin/mpic++
%{_libdir}/%{libname}/bin/mpif*
%{_mandir}/%{libname}/man1/mpic*
%{_mandir}/%{libname}/man1/mpif*
%{_includedir}/%{namearch}/
%{_libdir}/%{libname}/lib/*.so
%{_libdir}/%{libname}/lib/pkgconfig/
%config %{_sysconfdir}/rpm/macros.%{libname}

%files 3.2-doc
%defattr(-,root,root,-)
%{_docdir}/%{libname}
%{_mandir}/%{libname}/man3/

%global variant mpich
%global libname %{variant}
%global namearch %{variant}-%{_arch}

%files 3.0
%defattr(-,root,root,-)
%doc COPYRIGHT
%dir %{_libdir}/%{libname}
%dir %{_libdir}/%{libname}/lib
%dir %{_libdir}/%{libname}/bin
%{_libdir}/%{libname}/lib/*.so.*
%{_libdir}/%{libname}/bin/hydra*
%{_libdir}/%{libname}/bin/mpichversion
%{_libdir}/%{libname}/bin/mpiexec*
%{_libdir}/%{libname}/bin/mpirun
%dir %{python_sitearch}/%{libname}
%dir %{_fmoddir}/%{namearch}
%{_libdir}/%{libname}/bin/parkill
%dir %{_mandir}/%{libname}
%dir %{_mandir}/%{libname}/man1
%{_mandir}/%{libname}/man1/mpiexec*
%dir %{_sysconfdir}/modulefiles/mpi
%{_sysconfdir}/modulefiles/mpi/%{namearch}
%{_sysconfdir}/modulefiles/mpi/mpich-3.0-%{_arch}

%files 3.0-autoload
%defattr(-,root,root,-)
%{_sysconfdir}/profile.d/%{namearch}.*

%files 3.0-devel
%defattr(-,root,root,-)
%{_libdir}/%{libname}/bin/mpicc
%{_libdir}/%{libname}/bin/mpicxx
%{_libdir}/%{libname}/bin/mpic++
%{_libdir}/%{libname}/bin/mpif*
%{_mandir}/%{libname}/man1/mpic*
%{_mandir}/%{libname}/man1/mpif*
%config %{_sysconfdir}/%{namearch}/
%{_sysconfdir}/mpich-3.0-%{_arch}
%{_includedir}/%{namearch}/
%{_libdir}/%{libname}/lib/*.so
%{_libdir}/%{libname}/lib/pkgconfig/
%config %{_sysconfdir}/rpm/macros.%{libname}

%files 3.0-doc
%defattr(-,root,root,-)
%{_docdir}/%{libname}
%{_mandir}/%{libname}/man3/

%changelog
* Fri Jul 29 2016 Michal Schmidt <mschmidt@redhat.com> - 3.2-2
- Remove bad rpath in two binaries in mpich-3.2.
- Restore trimming of shebang lines in config files in mpich-3.0-devel.
- Related: rhbz1091532

* Wed Jun 22 2016 Michal Schmidt <mschmidt@redhat.com> - 3.2-1
- Update to upstream version mpich-3.2 with patches from Fedora.
- Keep 3.0.4 as 'mpich-3.0' for backwards compatibility.
- Resolves: rhbz1091532
- Resolves: rhbz1142117
- Resolves: rhbz1148992 

* Wed Sep 10 2014 Yaakov Selkowitz <yselkowi@redhat.com> - 3.0.4-8
- Do not use -m64 on AArch64
  Resolves: rhbz1077315

* Mon Mar 3 2014 Jay Fenlason <fenlason@redhat.com> - 3.0.4-7
- Update build flags to fix
  Resolves: rhbz1070778

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 3.0.4-6
- Mass rebuild 2014-01-24

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 3.0.4-5
- Mass rebuild 2013-12-27

* Fri Oct 4 2013 Jay Fenlason <fenlason@redhat.com> 3.0.4-4.el7
- Fix the module file to contain all the definitions we expect.
  Resolves: rhbz1001469

* Wed Oct 2 2013 Jay Fenlason <fenlason@redhat.com> 3.0.4-3.el7
- Fix macros.mpich
  Resolves: rhbz1001469

* Fri Sep 6 2013 Jay Fenlason <fenlason@redhat.com> 3.0.4-1.el7
- Initial import for RHEL, using sanitized source tarball.

