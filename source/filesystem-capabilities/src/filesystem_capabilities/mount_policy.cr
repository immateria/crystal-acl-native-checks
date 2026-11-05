module Filesystem::Capabilities
  # Whether a relative open may leave the file system its starting folder is
  # on. Allow follows ordinary entries, mounted folders included.
  # StayOnRootMount refuses a folder on another mount: Linux's openat2 with
  # RESOLVE_NO_XDEV for the whole path, and on macOS a walk that checks each
  # opened step's fstatfs, so APFS firmlinks count as crossings.
  # StayOnRootDevice refuses a step whose st_dev differs, as find -x does;
  # macOS presents its boot volume group as one device, and on Linux a bind
  # mount of one file system is not a crossing. A refused step raises an
  # EntryError with EXDEV. Neither policy promises root ancestry or general
  # confinement, and Windows refuses both (macOS parity design §3.2).
  enum MountPolicy
    Allow
    StayOnRootMount
    StayOnRootDevice
  end
end
