package server

import "errors"

func (nfs *NetworkfilterServer) cleanUpFqQdisc() error {
	if nfs.fqQdisc != nil {
		if err := nfs.tcConnection.Qdisc().Delete(nfs.fqQdisc); err != nil {
			return err
		}
	}
	nfs.fqQdisc = nil
	return nil
}

func (nfs *NetworkfilterServer) cleanUpClsactQdisc() error {
	if nfs.clsactQdisc != nil {
		if err := nfs.tcConnection.Qdisc().Delete(nfs.clsactQdisc); err != nil {
			return err
		}
	}
	nfs.clsactQdisc = nil
	return nil
}

func (nfs *NetworkfilterServer) cleanUpConnection() error {
	if nfs.tcConnection != nil {
		if err := nfs.cleanUpClsactQdisc(); err != nil {
			return err
		}
		if err := nfs.cleanUpFqQdisc(); err != nil {
			return err
		}
		if err := nfs.tcConnection.Close(); err != nil {
			return err
		}
		nfs.tcConnection = nil
		return nil
	} else {
		return errors.New("no tcConnection found")
	}
}

func (nfs *NetworkfilterServer) CleanUp() error {
	if err := nfs.cleanUpConnection(); err != nil {
		return err
	}
	for _, tshaperProgr := range nfs.tShaperEbpfPrograms {
		err := tshaperProgr.Close()
		if err != nil {
			return err
		}
	}
	for _, delayGenProgr := range nfs.delayGenEbpfPrograms {
		err := delayGenProgr.Close()
		if err != nil {
			return err
		}
	}
	for _, duplGenProgr := range nfs.duplGenEbpfPrograms {
		err := duplGenProgr.Close()
		if err != nil {
			return err
		}
	}
	for _, bitflipGenProgr := range nfs.bitflipGenEbpfPrograms {
		err := bitflipGenProgr.Close()
		if err != nil {
			return err
		}
	}
	for _, bwManagerProgr := range nfs.bwManagerEbpfPrograms {
		err := bwManagerProgr.Close()
		if err != nil {
			return err
		}
	}
	for _, link := range nfs.attachedLinks {
		err := link.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
