require "./model"

class Filesystem::AccessControl::Linux::ACL
  # Replace or insert an entry. A mask is never recalculated implicitly.
  def with_entry(entry : Entry, *, mask : Permissions? = nil) : ACL
    edited = @entries.reject { |old| old.tag == entry.tag && old.id == entry.id }
    edited << entry
    if mask
      edited.reject! { |old| old.tag.mask? }
      edited << Entry.new(Tag::Mask, mask)
    end
    ACL.new(edited.sort_by { |item| {item.tag.value, item.id || 0_u32} })
  end

  def without(tag : Tag, id : UInt32? = nil) : ACL
    ACL.new(@entries.reject { |entry| entry.tag == tag && entry.id == id })
  end

  # Explicitly widen/narrow the mask to the union of the group-class entries.
  def with_recalculated_mask : ACL
    permissions = Permissions::None
    @entries.each do |entry|
      permissions |= entry.permissions if entry.tag.user? || entry.tag.group? || entry.tag.owning_group?
    end
    with_entry(Entry.new(Tag::Mask, permissions))
  end
end
