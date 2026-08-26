module github.com/corezt/ztxbas/quickstarts/go

go 1.22

require github.com/corezt/ztxbas/sdk-go v0.0.0

// Use the SDK from the sibling directory in this monorepo. When the
// SDK is published, remove this replace and pin to a released tag.
replace github.com/corezt/ztxbas/sdk-go => ../../sdk-go
