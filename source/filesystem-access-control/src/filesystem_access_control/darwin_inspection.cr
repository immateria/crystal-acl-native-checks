{% skip_file unless flag?(:darwin) %}

# Darwin inspection imports descriptor capture and its authoritative snapshot.
require "./darwin/model"
require "./darwin/native"
require "./darwin/principals"
require "./darwin/reader"
