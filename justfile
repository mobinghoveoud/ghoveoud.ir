alias run := hugo-server

default:
    @just --list --unsorted

hugo-server port:
    hugo server -D -p {{ port }}
