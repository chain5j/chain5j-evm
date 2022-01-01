// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package evm

import (
	"github.com/chain5j/chain5j-pkg/types"
	"github.com/chain5j/chain5j-protocol/models"
	"github.com/chain5j/chain5j-protocol/models/statetype"
	"github.com/chain5j/chain5j-protocol/protocol"
	"math/big"
)

// StateDB is an EVM database for full state querying.
type StateDB interface {
	CreateAccount(types.Address)

	SubBalance(types.Address, *big.Int)
	AddBalance(types.Address, *big.Int)
	GetBalance(types.Address) *big.Int

	GetNonce(types.Address) uint64
	SetNonce(types.Address, uint64)

	GetCodeHash(types.Address) types.Hash
	GetCode(types.Address) []byte
	SetCode(types.Address, []byte)
	GetCodeSize(types.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetCommittedState(types.Address, types.Hash) types.Hash
	GetState(types.Address, types.Hash) types.Hash
	SetState(types.Address, types.Hash, types.Hash)

	Suicide(types.Address) bool
	HasSuicided(types.Address) bool

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for suicided accounts.
	Exist(types.Address) bool
	// Empty returns whether the given account is empty. Empty
	// is defined according to EIP161 (balance = nonce = code = 0).
	Empty(types.Address) bool

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(*statetype.Log)
	AddPreimage(types.Hash, []byte)

	ForEachStorage(types.Address, func(types.Hash, types.Hash) bool) error
}

// CallContext provides a basic interface for the EVM calling conventions. The EVM
// depends on this context being implemented for doing subcalls and initialising new EVM contracts.
type CallContext interface {
	// Call another contract
	Call(caller protocol.ContractRef, addr types.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error)
	// Take another's contract code and protocolecute within our own context
	CallCode(caller protocol.ContractRef, addr types.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error)
	// Same as CallCode except sender and value is propagated from parent to child scope
	DelegateCall(caller protocol.ContractRef, addr types.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error)
	StaticCall(caller protocol.ContractRef, addr types.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error)
	// Create a new contract
	Create(caller protocol.ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error)
	Create2(caller protocol.ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error)
	ChainConfig() *models.ChainConfig
}
