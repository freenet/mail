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
}
