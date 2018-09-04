@echo off
SET sigflow_path=%~dp0
ruby -I "%sigflow_path%src" -W0 "%sigflow_path%src/sigflow.rb" %*