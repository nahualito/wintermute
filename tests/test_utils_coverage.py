# -*- coding: utf-8 -*-
from wintermute.cloud.aws import AWSAccount, AWSService, AWSServiceType, IAMUser
from wintermute.core import BoundObjectRef, Device, Operation, TestCaseRun
from wintermute.utils.coverage import analyze_coverage


def test_analyze_coverage() -> None:
    op = Operation(operation_name="coverage_test")

    # 1. Add assets
    dev = Device(hostname="attacker")
    op.devices.append(dev)

    acc = AWSAccount(name="test-acc", account_id="123456789012")
    user = IAMUser(username="test-user", arn="arn:aws:iam::123456789012:user/test-user")
    acc.iamusers.append(user)

    svc = AWSService(
        service_type=AWSServiceType.S3,
        name="test-bucket",
        arn="arn:aws:s3:::test-bucket",
    )
    acc.services.append(svc)
    op.cloud_accounts.append(acc)

    # 2. Add test runs
    # Run targeting S3
    run1 = TestCaseRun(
        run_id="run1",
        test_case_code="AWS-S3-001",
        bound=[
            BoundObjectRef(
                kind="peripheral", object_id="arn:aws:s3:::test-bucket", alias="bucket"
            )
        ],
    )
    # Run targeting IAM user
    run2 = TestCaseRun(
        run_id="run2",
        test_case_code="AWS-IAM-001",
        bound=[BoundObjectRef(kind="peripheral", object_id="test-user", alias="user")],
    )
    # Run targeting Device
    run3 = TestCaseRun(
        run_id="run3",
        test_case_code="GEN-SCAN-001",
        bound=[BoundObjectRef(kind="device", object_id="attacker", alias="host")],
    )
    # Run targeting UNKNOWN (unbound)
    run4 = TestCaseRun(
        run_id="run4",
        test_case_code="AWS-LAMBDA-001",
        bound=[
            BoundObjectRef(kind="peripheral", object_id="unknown-arn", alias="lambda")
        ],
    )
    # Run with NO binding
    run5 = TestCaseRun(run_id="run5", test_case_code="MISC-001", bound=[])

    op.test_runs = [run1, run2, run3, run4, run5]

    # 3. Analyze
    stats = analyze_coverage(op)

    assert stats["S3"] == 1
    assert stats["IAM"] == 1
    assert stats["OSINT/GLOBAL"] == 1
    assert stats["Unbound (LAMBDA)"] == 1
    assert stats["GLOBAL_MISC"] == 1
