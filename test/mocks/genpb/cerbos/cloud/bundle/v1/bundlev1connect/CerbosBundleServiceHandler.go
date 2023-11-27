// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by mockery v2.38.0. DO NOT EDIT.

package mockbundlev1connect

import (
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"

	connect "connectrpc.com/connect"

	context "context"

	mock "github.com/stretchr/testify/mock"
)

// CerbosBundleServiceHandler is an autogenerated mock type for the CerbosBundleServiceHandler type
type CerbosBundleServiceHandler struct {
	mock.Mock
}

type CerbosBundleServiceHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *CerbosBundleServiceHandler) EXPECT() *CerbosBundleServiceHandler_Expecter {
	return &CerbosBundleServiceHandler_Expecter{mock: &_m.Mock}
}

// GetBundle provides a mock function with given fields: _a0, _a1
func (_m *CerbosBundleServiceHandler) GetBundle(_a0 context.Context, _a1 *connect.Request[bundlev1.GetBundleRequest]) (*connect.Response[bundlev1.GetBundleResponse], error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetBundle")
	}

	var r0 *connect.Response[bundlev1.GetBundleResponse]
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *connect.Request[bundlev1.GetBundleRequest]) (*connect.Response[bundlev1.GetBundleResponse], error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *connect.Request[bundlev1.GetBundleRequest]) *connect.Response[bundlev1.GetBundleResponse]); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*connect.Response[bundlev1.GetBundleResponse])
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *connect.Request[bundlev1.GetBundleRequest]) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CerbosBundleServiceHandler_GetBundle_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBundle'
type CerbosBundleServiceHandler_GetBundle_Call struct {
	*mock.Call
}

// GetBundle is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *connect.Request[bundlev1.GetBundleRequest]
func (_e *CerbosBundleServiceHandler_Expecter) GetBundle(_a0 interface{}, _a1 interface{}) *CerbosBundleServiceHandler_GetBundle_Call {
	return &CerbosBundleServiceHandler_GetBundle_Call{Call: _e.mock.On("GetBundle", _a0, _a1)}
}

func (_c *CerbosBundleServiceHandler_GetBundle_Call) Run(run func(_a0 context.Context, _a1 *connect.Request[bundlev1.GetBundleRequest])) *CerbosBundleServiceHandler_GetBundle_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*connect.Request[bundlev1.GetBundleRequest]))
	})
	return _c
}

func (_c *CerbosBundleServiceHandler_GetBundle_Call) Return(_a0 *connect.Response[bundlev1.GetBundleResponse], _a1 error) *CerbosBundleServiceHandler_GetBundle_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CerbosBundleServiceHandler_GetBundle_Call) RunAndReturn(run func(context.Context, *connect.Request[bundlev1.GetBundleRequest]) (*connect.Response[bundlev1.GetBundleResponse], error)) *CerbosBundleServiceHandler_GetBundle_Call {
	_c.Call.Return(run)
	return _c
}

// WatchBundle provides a mock function with given fields: _a0, _a1
func (_m *CerbosBundleServiceHandler) WatchBundle(_a0 context.Context, _a1 *connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse]) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for WatchBundle")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse]) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CerbosBundleServiceHandler_WatchBundle_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WatchBundle'
type CerbosBundleServiceHandler_WatchBundle_Call struct {
	*mock.Call
}

// WatchBundle is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *connect.BidiStream[bundlev1.WatchBundleRequest,bundlev1.WatchBundleResponse]
func (_e *CerbosBundleServiceHandler_Expecter) WatchBundle(_a0 interface{}, _a1 interface{}) *CerbosBundleServiceHandler_WatchBundle_Call {
	return &CerbosBundleServiceHandler_WatchBundle_Call{Call: _e.mock.On("WatchBundle", _a0, _a1)}
}

func (_c *CerbosBundleServiceHandler_WatchBundle_Call) Run(run func(_a0 context.Context, _a1 *connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse])) *CerbosBundleServiceHandler_WatchBundle_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse]))
	})
	return _c
}

func (_c *CerbosBundleServiceHandler_WatchBundle_Call) Return(_a0 error) *CerbosBundleServiceHandler_WatchBundle_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CerbosBundleServiceHandler_WatchBundle_Call) RunAndReturn(run func(context.Context, *connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse]) error) *CerbosBundleServiceHandler_WatchBundle_Call {
	_c.Call.Return(run)
	return _c
}

// NewCerbosBundleServiceHandler creates a new instance of CerbosBundleServiceHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCerbosBundleServiceHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *CerbosBundleServiceHandler {
	mock := &CerbosBundleServiceHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
