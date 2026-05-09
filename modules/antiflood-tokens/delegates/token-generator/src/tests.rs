use super::*;

mod token_assignment {
    use std::sync::LazyLock;

    use super::*;
    use chrono::{NaiveDate, Timelike};
    use freenet_aft_interface::Tier;

    fn get_assignment_date(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        let naive = NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    }

    const TEST_TIER: Tier = Tier::Day1;
    const MAX_DURATION_1Y: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 3600);

    // These tests exercise only `next_free_assignment` slot-scheduling logic;
    // the generator and signature fields on each `TokenAssignment` are never
    // verified here, so we fill them with dummy placeholder bytes.
    fn dummy_generator() -> Vec<u8> {
        vec![0u8; 1952]
    }

    fn dummy_signature() -> Vec<u8> {
        vec![1u8; 64]
    }

    static ID: LazyLock<ContractInstanceId> = LazyLock::new(|| {
        let rnd = [1; 32];
        let mut gen_ = arbitrary::Unstructured::new(&rnd);
        gen_.arbitrary().unwrap()
    });

    #[test]
    fn free_spot_first() {
        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![TokenAssignment {
                tier: TEST_TIER,
                time_slot: get_assignment_date(2023, 1, 25),
                generator: dummy_generator(),
                signature: dummy_signature(),
                assignment_hash: [0; 32],
                token_record: *ID,
            }],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_1Y, *ID).unwrap(),
            get_assignment_date(2023, 1, 27),
        );
        assert_eq!(assignment.unwrap(), get_assignment_date(2022, 1, 27));
    }

    #[test]
    fn free_spot_skip_first() {
        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 27),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2023, 1, 26),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
            ],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_1Y, *ID).unwrap(),
            get_assignment_date(2023, 1, 27).with_minute(1).unwrap(),
        );
        assert_eq!(assignment.unwrap(), get_assignment_date(2022, 1, 28));
    }

    #[test]
    fn free_spot_skip_gap_1() {
        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 27),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 29),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
            ],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_1Y, *ID).unwrap(),
            get_assignment_date(2023, 1, 27),
        );
        assert_eq!(assignment.unwrap(), get_assignment_date(2022, 1, 28));

        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 27),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 28),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
                TokenAssignment {
                    tier: TEST_TIER,
                    time_slot: get_assignment_date(2022, 1, 30),
                    generator: dummy_generator(),
                    signature: dummy_signature(),
                    assignment_hash: [0; 32],
                    token_record: *ID,
                },
            ],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_1Y, *ID).unwrap(),
            get_assignment_date(2023, 1, 27).with_minute(1).unwrap(),
        );
        assert_eq!(assignment.unwrap(), get_assignment_date(2022, 1, 29));
    }

    #[test]
    fn free_spot_new() {
        let records = TokenAllocationRecord::new(HashMap::new());
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_1Y, *ID).unwrap(),
            get_assignment_date(2023, 1, 27).with_minute(1).unwrap(),
        );
        assert_eq!(assignment.unwrap(), get_assignment_date(2022, 1, 28));
    }

    // Cap-enforcement coverage (#179). The user-visible "no free slot"
    // path fires when every slot in the closed window
    // `[normalized - max_age, normalized]` is already assigned. With
    // Day1 tier + 3-day max_age that window contains 4 daily slots
    // (e.g. 01-24, 01-25, 01-26, 01-27 when `now == 01-27`); fill all
    // four and `next_free_assignment` must return None so the delegate
    // emits `Failure(NoFreeSlot)`.
    const MAX_DURATION_3D: std::time::Duration = std::time::Duration::from_secs(3 * 24 * 3600);

    #[test]
    fn day1_window_exhausted_returns_none() {
        // Reference "now" — Day1 normalize_to_next of a midnight value is
        // a no-op, so the window is exactly [now - 3d, now] and the
        // valid slot dates are 2023-01-24, 2023-01-25, 2023-01-26.
        let now = get_assignment_date(2023, 1, 27);
        let mk = |y, m, d| TokenAssignment {
            tier: TEST_TIER,
            time_slot: get_assignment_date(y, m, d),
            generator: dummy_generator(),
            signature: dummy_signature(),
            assignment_hash: [0; 32],
            token_record: *ID,
        };
        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![
                mk(2023, 1, 24),
                mk(2023, 1, 25),
                mk(2023, 1, 26),
                mk(2023, 1, 27),
            ],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_3D, *ID).unwrap(),
            now,
        );
        assert!(
            assignment.is_none(),
            "saturated 3-day Day1 window must return None; got {assignment:?}"
        );
    }

    #[test]
    fn day1_window_not_quite_exhausted_returns_remaining_slot() {
        // Same 3-day window but with the middle slot free. Confirms the
        // assertion in the previous test isn't a false positive — the
        // function actually scans for free slots and only returns None
        // when there are none.
        let now = get_assignment_date(2023, 1, 27);
        let mk = |y, m, d| TokenAssignment {
            tier: TEST_TIER,
            time_slot: get_assignment_date(y, m, d),
            generator: dummy_generator(),
            signature: dummy_signature(),
            assignment_hash: [0; 32],
            token_record: *ID,
        };
        let records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![mk(2023, 1, 24), mk(2023, 1, 26)],
        )]));
        let assignment = records.next_free_assignment(
            &AllocationCriteria::new(TEST_TIER, MAX_DURATION_3D, *ID).unwrap(),
            now,
        );
        assert_eq!(
            assignment,
            Some(get_assignment_date(2023, 1, 25)),
            "middle slot 2023-01-25 must be picked"
        );
    }

    #[test]
    fn day1_freeing_a_slot_after_exhaustion_restores_allocation() {
        // Saturate the 3-day window, then drop the newest assignment
        // and confirm the allocator can pick it up again. Mirrors the
        // user-visible "wait until a slot frees, then send" path.
        let now = get_assignment_date(2023, 1, 27);
        let mk = |y, m, d| TokenAssignment {
            tier: TEST_TIER,
            time_slot: get_assignment_date(y, m, d),
            generator: dummy_generator(),
            signature: dummy_signature(),
            assignment_hash: [0; 32],
            token_record: *ID,
        };
        let mut records = TokenAllocationRecord::new(HashMap::from_iter([(
            TEST_TIER,
            vec![
                mk(2023, 1, 24),
                mk(2023, 1, 25),
                mk(2023, 1, 26),
                mk(2023, 1, 27),
            ],
        )]));
        let criteria = AllocationCriteria::new(TEST_TIER, MAX_DURATION_3D, *ID).unwrap();
        assert!(records.next_free_assignment(&criteria, now).is_none());

        records.get_mut_tier(&TEST_TIER).unwrap().pop(); // drop 2023-01-27
        assert!(
            records.next_free_assignment(&criteria, now).is_some(),
            "freeing the newest slot must restore allocation"
        );
    }
}
