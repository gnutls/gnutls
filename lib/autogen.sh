#!/bin/sh

for f in po/*.po.in; do
    cp $f `echo $f | sed 's/.in//'`
done
autoreconf --install
