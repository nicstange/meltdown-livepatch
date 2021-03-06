#
# tar-up.sh - script for building a kGraft rpm package
#
# Copyright (c) 2014 SUSE
#  Author: Miroslav Benes <mbenes@suse.cz>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#!/bin/bash

# options
until [ "$#" = "0" ] ; do
  case "$1" in
    --dir=*)
      build_dir=${1#*=}
      shift
      ;;
    -d|--dir)
      build_dir=$2
      shift 2
      ;;
    -h|--help|-v|--version)
	cat <<EOF

${0##*/} prepares a kGraft module package for submission into build service

these options are recognized:
    -d, --dir=DIR      create package in DIR instead of default kgraft-mod-source

EOF
	exit 1
	;;
    *)
      echo "unknown option '$1'" >&2
      exit 1
      ;;
  esac
done

# builddir
[ -z "$build_dir" ] && build_dir=kgraft-mod-source
if [ -z "$build_dir" ]; then
    echo "Please define the build directory with the --dir option" >&2
    exit 1
fi

rm -f "$build_dir"/*
mkdir -p "$build_dir"

# archives
# pack all directories with live patches
#	rpm/, scripts/ and $build_dir (if local) are excluded
build_dir_trim=$(basename $build_dir)
archives=$(ls -d */ | cut -f1 -d'/' | sed -r "s/rpm|scripts|$build_dir_trim//")
for archive in $archives; do
	echo "$archive.tar.bz2"
	tar cfj $build_dir/$archive.tar.bz2 $archive
done

# install to builddir
source $(dirname $0)/release-version.sh

install -m 644 kgr_patch_main.c $build_dir
install -m 644 rpm/kgraft-patch.spec $build_dir/kgraft-patch-"$RELEASE".spec
scripts/register-patches.sh $build_dir/kgr_patch_main.c $build_dir/kgraft-patch-"$RELEASE".spec
install -m 644 rpm/config.sh $build_dir/config.sh
install -m 644 shadow.c $build_dir
install -m 644 shadow.h $build_dir

# create new Makefile in $build_dir
scripts/create-makefile.sh $build_dir

# timestamp
tsfile=source-timestamp
ts=$(git show --pretty=format:%ct HEAD | head -n 1)
date "+%Y-%m-%d %H:%M:%S %z" -d "1970-01-01 00:00 UTC $ts seconds" >$build_dir/$tsfile
echo "GIT Revision: $(git rev-parse HEAD)" >> $build_dir/$tsfile
branch=$(sed -ne 's|^ref: refs/heads/||p' .git/HEAD 2>/dev/null)
if test -n "$branch"; then
	echo "GIT Branch: $branch" >>$build_dir/$tsfile
fi

# ExclusiveArch
if [[ $RELEASE == SLE12-SP3* ]]; then
	excarch='ppc64le x86_64'
else
	excarch='x86_64'
fi

sed -i \
	-e "s/@@RELEASE@@/$RELEASE/g" \
	-e "/@@SOURCE_TIMESTAMP@@/ {
		e echo -n 'Source timestamp: '; cat $build_dir/$tsfile
		d
	}" \
	-e "s/@@EXCARCH@@/$excarch/" \
	$build_dir/kgraft-patch-"$RELEASE".spec

# changelog
changelog=$build_dir/kgraft-patch-"$RELEASE".changes
scripts/gitlog2changes.pl HEAD -- > "$changelog"
