use bitflags::bitflags;

bitflags! {
    /// Per-packet behavioral flags.
    ///
    /// Bits 0 and 2 (formerly ENCRYPTED / SIGNED in the legacy drafts) are
    /// reserved: transport security is TLS, not a per-packet concern.
    /// Bits 8-9 form a two-bit priority field; use [`PacketFlags::priority`]
    /// and [`PacketFlags::with_priority`] rather than testing them directly.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketFlags: u16 {
        const COMPRESSED      = 1 << 1;
        const REQUIRES_ACK    = 1 << 3;

        const TRANSFER_START  = 1 << 4;
        const TRANSFER_END    = 1 << 5;
        const TRANSFER_ABORT  = 1 << 6;
        const TRANSFER_RESUME = 1 << 7;

        const PRIORITY_BIT0   = 1 << 8;
        const PRIORITY_BIT1   = 1 << 9;

        const FRAGMENTED      = 1 << 12;
        const MORE_FRAGMENTS  = 1 << 13;
        const SYSTEM_MESSAGE  = 1 << 14;

        // Preserve unknown bits so future protocol versions round-trip.
        const _ = !0;
    }
}

/// Packet priority, encoded in flag bits 8-9.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl PacketFlags {
    pub fn priority(self) -> Priority {
        match (self.bits() >> 8) & 0b11 {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => Priority::Critical,
        }
    }

    pub fn with_priority(self, priority: Priority) -> Self {
        let cleared = self.bits() & !(0b11 << 8);
        Self::from_bits_retain(cleared | ((priority as u16) << 8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_round_trips() {
        for p in [
            Priority::Low,
            Priority::Normal,
            Priority::High,
            Priority::Critical,
        ] {
            let flags = PacketFlags::REQUIRES_ACK.with_priority(p);
            assert_eq!(flags.priority(), p);
            assert!(flags.contains(PacketFlags::REQUIRES_ACK));
        }
    }

    #[test]
    fn with_priority_overwrites_previous() {
        let flags = PacketFlags::empty()
            .with_priority(Priority::Critical)
            .with_priority(Priority::Low);
        assert_eq!(flags.priority(), Priority::Low);
    }
}
