#!/bin/sh
case "$0" in
    */*) helper_dir=${0%/*} ;;
    *) helper_dir=/data/workspace ;;
esac
exec /usr/bin/python3 -B -S "$helper_dir/rm_tmp_file.py" "$@"
