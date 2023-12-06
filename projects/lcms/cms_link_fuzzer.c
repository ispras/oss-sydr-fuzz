//---------------------------------------------------------------------------------
//
//  Little Color Management System
//  Copyright (c) 1998-2023 Marti Maria Saguer
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//---------------------------------------------------------------------------------
#include "lcms2.h"
#include "string.h"
#include <stdint.h>
#include <stdlib.h>
// ---------------------------------------------------------------------------------

static char *Description = "Devicelink profile";
static char *Copyright = "No copyright, use freely";
static int Intent = INTENT_PERCEPTUAL;
static char *cOutProf = "devicelink.icc";
static int PrecalcMode = 1;
static int NumOfGridPoints = 0;

static cmsFloat64Number ObserverAdaptationState =
    1.0; // According ICC 4.2 this is the default

static cmsBool BlackPointCompensation = FALSE;

static cmsFloat64Number InkLimit = 400;
static cmsBool lUse8bits = FALSE;
static cmsBool TagResult = FALSE;
static cmsBool KeepLinearization = FALSE;
static cmsFloat64Number Version = 4.3;

// Set the copyright and description
static cmsBool SetTextTags(cmsHPROFILE hProfile) {
  cmsMLU *DescriptionMLU, *CopyrightMLU;
  cmsBool rc = FALSE;
  cmsContext ContextID = cmsGetProfileContextID(hProfile);

  DescriptionMLU = cmsMLUalloc(ContextID, 1);
  CopyrightMLU = cmsMLUalloc(ContextID, 1);

  if (DescriptionMLU == NULL || CopyrightMLU == NULL)
    goto Error;

  if (!cmsMLUsetASCII(DescriptionMLU, "en", "US", Description))
    goto Error;
  if (!cmsMLUsetASCII(CopyrightMLU, "en", "US", Copyright))
    goto Error;

  if (!cmsWriteTag(hProfile, cmsSigProfileDescriptionTag, DescriptionMLU))
    goto Error;
  if (!cmsWriteTag(hProfile, cmsSigCopyrightTag, CopyrightMLU))
    goto Error;

  rc = TRUE;

Error:

  if (DescriptionMLU)
    cmsMLUfree(DescriptionMLU);
  if (CopyrightMLU)
    cmsMLUfree(CopyrightMLU);
  return rc;
}

uint8_t getbit(uint8_t data, uint8_t i) {
  return ((uint8_t)(data << (7 - i))) >> 7;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int i, nargs = 2;
  cmsHPROFILE Profiles[nargs];
  cmsHPROFILE hProfile;
  cmsUInt32Number dwFlags;
  cmsHTRANSFORM hTransform = NULL;

  // Open all profiles
  memset(Profiles, 0, sizeof(Profiles));
  const uint8_t *profile = data + 3;
  size_t profile_size = size - 3;
  Profiles[1] = cmsOpenProfileFromMem(profile, profile_size);
  if (Profiles[1] == NULL)
    goto Cleanup;

  {
    cmsColorSpaceSignature EndingColorSpace = cmsGetColorSpace(Profiles[1]);
    Profiles[0] = cmsCreateInkLimitingDeviceLink(EndingColorSpace, 200);
  }

  // Set the flags
  dwFlags = cmsFLAGS_KEEP_SEQUENCE;
  switch (data[0]) {

  case 0:
    dwFlags |= cmsFLAGS_LOWRESPRECALC;
    break;
  case 1:
    dwFlags |= cmsFLAGS_HIGHRESPRECALC;
    break;
  case 2:
    dwFlags |= cmsFLAGS_GRIDPOINTS(data[1]);
    break;
  default:
    break;
  }
  if (getbit(data[2], 0))
    dwFlags |= cmsFLAGS_BLACKPOINTCOMPENSATION;

  if (getbit(data[2], 1))
    dwFlags |= cmsFLAGS_GUESSDEVICECLASS;

  if (getbit(data[2], 2))
    dwFlags |=
        cmsFLAGS_CLUT_PRE_LINEARIZATION | cmsFLAGS_CLUT_POST_LINEARIZATION;

  if (getbit(data[2], 3))
    dwFlags |= cmsFLAGS_8BITS_DEVICELINK;

  cmsSetAdaptationState(ObserverAdaptationState);

  // Create the color transform. Specify 0 for the format is safe as the
  // transform is intended to be used only for the devicelink.
  hTransform = cmsCreateMultiprofileTransform(Profiles, nargs, 0, 0, Intent,
                                              dwFlags | cmsFLAGS_NOOPTIMIZE);
  if (hTransform == NULL) {
    goto Cleanup;
  }

  hProfile = cmsTransform2DeviceLink(hTransform, Version, dwFlags);
  if (hProfile == NULL) {
    goto Cleanup;
  }

  SetTextTags(hProfile);
  cmsSetHeaderRenderingIntent(hProfile, Intent);

  cmsSaveProfileToFile(hProfile, "/dev/null");

  cmsCloseProfile(hProfile);

Cleanup:

  if (hTransform != NULL)
    cmsDeleteTransform(hTransform);
  for (i = 0; i < nargs; i++) {

    if (Profiles[i] != NULL)
      cmsCloseProfile(Profiles[i]);
  }

  return 0;
}
