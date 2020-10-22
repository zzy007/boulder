// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"
	"github.com/tjfoc/gmsm/sm2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
)

// RegistrationAuthorityClientWrapper is the gRPC version of a core.RegistrationAuthority client
type RegistrationAuthorityClientWrapper struct {
	inner rapb.RegistrationAuthorityClient
}

func NewRegistrationAuthorityClient(inner rapb.RegistrationAuthorityClient) *RegistrationAuthorityClientWrapper {
	return &RegistrationAuthorityClientWrapper{inner}
}

func (rac RegistrationAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	req, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.NewRegistration(ctx, req)
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	r, err := pbToRegistration(response)
	return r, err
}

func (rac RegistrationAuthorityClientWrapper) NewAuthorization(ctx context.Context, authz core.Authorization, regID int64) (core.Authorization, error) {
	req, err := AuthzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := rac.inner.NewAuthorization(ctx, &rapb.NewAuthorizationRequest{Authz: req, RegID: regID})
	if err != nil {
		return core.Authorization{}, err
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return PBToAuthz(response)
}

func (rac RegistrationAuthorityClientWrapper) NewCertificate(ctx context.Context, csr core.CertificateRequest, regID int64) (core.Certificate, error) {
	response, err := rac.inner.NewCertificate(ctx, &rapb.NewCertificateRequest{Csr: csr.Bytes, RegID: regID})
	if err != nil {
		return core.Certificate{}, err
	}

	return PBToCert(response)
}

func (rac RegistrationAuthorityClientWrapper) UpdateRegistration(ctx context.Context, base, updates core.Registration) (core.Registration, error) {
	basePB, err := registrationToPB(base)
	if err != nil {
		return core.Registration{}, err
	}
	updatePB, err := registrationToPB(updates)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.UpdateRegistration(ctx, &rapb.UpdateRegistrationRequest{Base: basePB, Update: updatePB})
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (rac RegistrationAuthorityClientWrapper) PerformValidation(
	ctx context.Context,
	req *rapb.PerformValidationRequest) (*corepb.Authorization, error) {
	authz, err := rac.inner.PerformValidation(ctx, req)
	if err != nil {
		return nil, err
	}

	if authz == nil || !authorizationValid(authz) {
		return nil, errIncompleteResponse
	}

	return authz, nil
}

func (rac RegistrationAuthorityClientWrapper) RevokeCertificateWithReg(ctx context.Context, cert sm2.Certificate, code revocation.Reason, regID int64) error {
	_, err := rac.inner.RevokeCertificateWithReg(ctx, &rapb.RevokeCertificateWithRegRequest{
		Cert:  cert.Raw,
		Code:  int64(code),
		RegID: regID,
	})
	if err != nil {
		return err
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, reg core.Registration) error {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateRegistration(ctx, regPB)
	if err != nil {
		return err
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, auth core.Authorization) error {
	authzPB, err := AuthzToPB(auth)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateAuthorization(ctx, authzPB)
	if err != nil {
		return err
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) AdministrativelyRevokeCertificate(ctx context.Context, cert sm2.Certificate, code revocation.Reason, adminName string) error {
	_, err := rac.inner.AdministrativelyRevokeCertificate(ctx, &rapb.AdministrativelyRevokeCertificateRequest{
		Cert:      cert.Raw,
		Code:      int64(code),
		AdminName: adminName,
	})
	if err != nil {
		return err
	}

	return nil
}

func (ras *RegistrationAuthorityClientWrapper) NewOrder(ctx context.Context, request *rapb.NewOrderRequest) (*corepb.Order, error) {
	resp, err := ras.inner.NewOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (ras *RegistrationAuthorityClientWrapper) FinalizeOrder(ctx context.Context, request *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	resp, err := ras.inner.FinalizeOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

// RegistrationAuthorityServerWrapper is the gRPC version of a core.RegistrationAuthority server
type RegistrationAuthorityServerWrapper struct {
	inner core.RegistrationAuthority
}

func NewRegistrationAuthorityServer(inner core.RegistrationAuthority) *RegistrationAuthorityServerWrapper {
	return &RegistrationAuthorityServerWrapper{inner}
}

func (ras *RegistrationAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	if request == nil || !newRegistrationValid(request) {
		return nil, errIncompleteRequest
	}
	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}
	newReg, err := ras.inner.NewRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}
	return registrationToPB(newReg)
}

func (ras *RegistrationAuthorityServerWrapper) NewAuthorization(ctx context.Context, request *rapb.NewAuthorizationRequest) (*corepb.Authorization, error) {
	if request == nil || request.Authz.Identifier == "" || request.RegID == 0 {
		return nil, errIncompleteRequest
	}
	authz, err := PBToAuthz(request.Authz)
	if err != nil {
		return nil, err
	}
	newAuthz, err := ras.inner.NewAuthorization(ctx, authz, request.RegID)
	if err != nil {
		return nil, err
	}
	return AuthzToPB(newAuthz)
}

func (ras *RegistrationAuthorityServerWrapper) NewCertificate(ctx context.Context, request *rapb.NewCertificateRequest) (*corepb.Certificate, error) {
	if request == nil || request.Csr == nil || request.RegID == 0 {
		return nil, errIncompleteRequest
	}
	csr, err := sm2.ParseCertificateRequest(request.Csr)
	if err != nil {
		return nil, err
	}
	cert, err := ras.inner.NewCertificate(ctx, core.CertificateRequest{CSR: csr, Bytes: request.Csr}, request.RegID)
	if err != nil {
		return nil, err
	}
	return CertToPB(cert), nil
}

func (ras *RegistrationAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *rapb.UpdateRegistrationRequest) (*corepb.Registration, error) {
	if request == nil || !registrationValid(request.Base) {
		return nil, errIncompleteRequest
	}
	base, err := pbToRegistration(request.Base)
	if err != nil {
		return nil, err
	}
	update, err := pbToRegistration(request.Update)
	if err != nil {
		return nil, err
	}
	newReg, err := ras.inner.UpdateRegistration(ctx, base, update)
	if err != nil {
		return nil, err
	}
	return registrationToPB(newReg)
}

func (ras *RegistrationAuthorityServerWrapper) PerformValidation(
	ctx context.Context,
	request *rapb.PerformValidationRequest) (*corepb.Authorization, error) {
	if request == nil || !authorizationValid(request.Authz) {
		return nil, errIncompleteRequest
	}
	return ras.inner.PerformValidation(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) RevokeCertificateWithReg(ctx context.Context, request *rapb.RevokeCertificateWithRegRequest) (*corepb.Empty, error) {
	if request == nil || request.Cert == nil {
		return nil, errIncompleteRequest
	}
	cert, err := sm2.ParseCertificate(request.Cert)
	if err != nil {
		return nil, err
	}
	err = ras.inner.RevokeCertificateWithReg(ctx, *cert, revocation.Reason(request.Code), request.RegID)
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Empty, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}
	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}
	err = ras.inner.DeactivateRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}
	authz, err := PBToAuthz(request)
	if err != nil {
		return nil, err
	}
	err = ras.inner.DeactivateAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) AdministrativelyRevokeCertificate(ctx context.Context, request *rapb.AdministrativelyRevokeCertificateRequest) (*corepb.Empty, error) {
	if request == nil || request.Cert == nil || request.AdminName == "" {
		return nil, errIncompleteRequest
	}
	cert, err := sm2.ParseCertificate(request.Cert)
	if err != nil {
		return nil, err
	}
	err = ras.inner.AdministrativelyRevokeCertificate(ctx, *cert, revocation.Reason(request.Code), request.AdminName)
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) NewOrder(ctx context.Context, request *rapb.NewOrderRequest) (*corepb.Order, error) {
	if request == nil || request.RegistrationID == 0 {
		return nil, errIncompleteRequest
	}
	return ras.inner.NewOrder(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) FinalizeOrder(ctx context.Context, request *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	if request == nil || request.Order == nil || request.Csr == nil {
		return nil, errIncompleteRequest
	}

	return ras.inner.FinalizeOrder(ctx, request)
}
