#!/bin/bash -e
self=$(basename ${BASH_SOURCE[0]})
yell() { echo "$self: $*" >&2; }
die() { yell "$*"; exit 1; }
try() { "$@" || die "failed: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH

name=voluta
selfdir=$(realpath $(dirname ${BASH_SOURCE[0]}))
basedir=$(realpath ${selfdir}/../)
version_sh=${basedir}/version.sh
version=$(try ${version_sh} --version)
release=$(try ${version_sh} --release)
revision=$(try ${version_sh} --revision)
archive_tgz=${name}-${version}.tar.gz

builddir=${basedir}/build
buildauxdir=${builddir}/deb
autotoolsdir=${buildauxdir}/autotools/

debdate=$(date -R)
debsourcedir=${selfdir}/deb
debbuilddir=${buildauxdir}/debbuild
deborig_archive=${name}_${version}.orig.tar.gz
debrelease_archive=${name}_${version}-${release}.debian.tar.gz
debbuild_distdir=${debbuilddir}/${name}-${version}
debbuild_debiandir=${debbuild_distdir}/debian


# Prerequisites checks
run which aclocal
run which automake
run which libtoolize
run which rst2man
run which rst2html
run which basename
run which dpkg-buildpackage
run which dh

# Autotools build
run mkdir -p ${autotoolsdir}
run cd ${autotoolsdir}
run ${basedir}/bootstrap
run ${basedir}/configure "--enable-unitests=no"
run make
run make distcheck

# Prepare deb tree
run mkdir -p ${debbuilddir}
run mkdir -p ${debbuild_distdir}
run mkdir -p ${debbuild_debiandir}

# Copy and extract dist archives
run cp ${autotoolsdir}/${archive_tgz} ${debbuilddir}/
run cp ${autotoolsdir}/${archive_tgz} ${debbuilddir}/${deborig_archive}
run cp ${autotoolsdir}/${archive_tgz} ${debbuilddir}/${debrelease_archive}
run cd ${debbuilddir}
run tar xvfz ${archive_tgz}

# Prepare deb files
run cd ${basedir}
run mkdir -p ${debbuild_debiandir}/source
run cp ${debsourcedir}/format ${debbuild_debiandir}/source
run cp ${debsourcedir}/compat ${debbuild_debiandir}
run cp ${debsourcedir}/control ${debbuild_debiandir}
run cp ${debsourcedir}/copyright ${debbuild_debiandir}
run cp ${debsourcedir}/docs ${debbuild_debiandir}
run cp ${debsourcedir}/README.Debian ${debbuild_debiandir}
run cp ${debsourcedir}/rules ${debbuild_debiandir}


# Generate changelog
run sed \
  -e "s,[@]NAME[@],${name},g" \
  -e "s,[@]VERSION[@],${version},g" \
  -e "s,[@]RELEASE[@],${release},g" \
  -e "s,[@]REVISION[@],${revision},g" \
  ${debsourcedir}/changelog.in > ${debbuild_debiandir}/changelog

# Build deb package
run cd ${debbuild_distdir}
run dpkg-buildpackage -us -uc

# Copy debs to root of build-dir
run find ${debbuilddir}/ -type f -name ${name}_${version}'*.deb' \
  -exec cp {} ${builddir} \;

# Cleanup build staging area
run cd ${basedir}
run rm -rf ${buildauxdir}

# Bye ;)
run ls ${builddir}/${name}*.deb



