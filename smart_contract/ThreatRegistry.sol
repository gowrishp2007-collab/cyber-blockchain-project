// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatRegistry {

    struct ThreatRecord {
        uint256 threatId;
        string evidenceHash;
        uint256 timestamp;
        address reporter;
    }

    mapping(uint256 => ThreatRecord) private records;

    event ThreatRecorded(
        uint256 indexed threatId,
        string evidenceHash,
        uint256 timestamp,
        address indexed reporter
    );

    function recordThreat(
        uint256 _threatId,
        string memory _evidenceHash
    ) public {
        records[_threatId] = ThreatRecord(
            _threatId,
            _evidenceHash,
            block.timestamp,
            msg.sender
        );

        emit ThreatRecorded(
            _threatId,
            _evidenceHash,
            block.timestamp,
            msg.sender
        );
    }

    function getThreat(
        uint256 _threatId
    )
        public
        view
        returns (
            uint256 threatId,
            string memory evidenceHash,
            uint256 timestamp,
            address reporter
        )
    {
        ThreatRecord memory record = records[_threatId];

        return (
            record.threatId,
            record.evidenceHash,
            record.timestamp,
            record.reporter
        );
    }
}