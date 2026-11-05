# Internal retained-root ownership protocol shared by Linux, Darwin and Windows.
# An ordinary close waits for borrowed operations under Sync::Exclusive;
# a Boehm GC finalizer can claim the same OS resource without a Crystal Fiber.
# Do not name the finalizer-path method `finalize`: only Directory owns the
# collector hook and the native platform knows how to close its resource.
require "sync/exclusive"

class Filesystem::Capabilities::Directory
  private class RootLease(T)
    @borrowed : Sync::Exclusive(T)
    @claim : ::Atomic(T)

    def initialize(resource : T, @invalid : T)
      @claim = ::Atomic(T).new(resource)
      @borrowed = Sync::Exclusive.new(resource)
    end

    def closed? : Bool
      @borrowed.get == @invalid
    end

    # Existing opt-in providers borrow the retained root through this lock;
    # they must not store or independently close the supplied resource.
    def lock(& : T -> R) : R forall R
      @borrowed.lock { |resource| yield resource }
    end

    # Explicit close is serialized against all borrowers and invalidates
    # the retained root even if finalization has already claimed the token.
    def close(& : T ->) : Nil
      @borrowed.replace do |_resource|
        claim_once { |resource| yield resource }
        @invalid
      end
    end

    # No Sync::Exclusive, blocking lock, or fiber-aware operation may run on
    # the collector's finalizer thread. Only atomically claim and release.
    def release_on_finalization(& : T ->) : Nil
      claim_once { |resource| yield resource }
    end

    private def claim_once(& : T ->) : Nil
      resource = @claim.swap(@invalid)
      yield resource unless resource == @invalid
    end
  end
end
