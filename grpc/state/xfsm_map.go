package state

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/philipab/ebpf-proto/ebpf/bwmanager"
)

// update cases - bandwidth manager
const (
	UPDATE_CASE_1 uint32 = iota // starts at 0
	UPDATE_CASE_2
	UPDATE_CASE_3
	UPDATE_CASE_4
)

// packet actions (DROP / FORWARD) - bandwidth manager
const (
	DROP uint32 = iota // starts at 0
	FORWARD
)

// Eval conditions for state table - bandwidth manager
const (
	ERROR uint8 = iota
	TRUE
	FALSE
	ANY // wildcard (unused)
)

// IP protocol types (IPv4 / IPv6)
const (
	IPV4 uint16 = 0x0800
	IPV6 uint16 = 0x86DD
)

// State for state table - bandwidth manager
const (
	ZERO uint32 = iota // starts at 0
	ONE
)

// initialize / update the eXtensible Finite State Machine table (XFSM table)
func InitializeXfsmTable() error {
	newObjs := bwmanager.BwObjectsWrapper{}
	if err := bwmanager.LoadBwObjectsWrapper(&newObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}); err != nil {
		log.Fatalf("failed to load bw manager's objects: %v", err)
	}
	defer newObjs.Close()
	const xtpath = "/sys/fs/bpf/xfsm_table"
	xfsmTable, err := ebpf.LoadPinnedMap(xtpath, nil)
	if err != nil {
		log.Fatalf("Error opening map: %s\n", err)
	}
	defer xfsmTable.Close()
	if err := initializeXfsmTableHelper(xfsmTable, ZERO, IPV4, FALSE, ZERO, DROP, UPDATE_CASE_1); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ZERO, IPV4, TRUE, ONE, FORWARD, UPDATE_CASE_2); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ONE, IPV4, FALSE, ONE, DROP, UPDATE_CASE_3); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ONE, IPV4, TRUE, ONE, FORWARD, UPDATE_CASE_4); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ZERO, IPV6, FALSE, ZERO, DROP, UPDATE_CASE_1); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ZERO, IPV6, TRUE, ONE, FORWARD, UPDATE_CASE_2); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ONE, IPV6, FALSE, ONE, DROP, UPDATE_CASE_3); err != nil {
		return err
	}
	if err := initializeXfsmTableHelper(xfsmTable, ONE, IPV6, TRUE, ONE, FORWARD, UPDATE_CASE_4); err != nil {
		return err
	}
	// all keys/values were initialized or updated successfully
	return nil
}

func initializeXfsmTableHelper(xfsmTable *ebpf.Map, state uint32, etherType uint16, cond uint8, nextState uint32, packetAction uint32, updateFunction uint32) error {
	var xtkey bwmanager.XFSMTableKeyWrapper
	var xtleaf bwmanager.XFSMTableLeafWrapper
	xtkey.State = state
	xtkey.EtherType = etherType
	xtkey.Cond1 = cond

	xtleaf.NextState = nextState
	xtleaf.PacketAction = packetAction
	xtleaf.UpdateFunction = updateFunction
	if err := xfsmTable.Update(&xtkey, &xtleaf, 0); err != nil {
		return fmt.Errorf("error updating xfsmTable: %v", err)
	}
	return nil
}
