#! /bin/sh
SIGFLOW_BASE_DIR=$(dirname $0)
ruby -W0 -I$SIGFLOW_BASE_DIR/src $SIGFLOW_BASE_DIR/src/sigflow.rb "$@"

