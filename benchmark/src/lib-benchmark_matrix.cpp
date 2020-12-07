/*
 * @file lib-benchmark : library benchmark routines for comparison by build
 * @author TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This file benchmarks a small number of operations in order to exercise large
 * pieces of the library
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>
#include "math/matrix.h"


#include "palisade.h"

#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

#define RANGE RangeMultiplier(2)->Range(8, 8<<10)
/*
 * Context setup utility methods
 */

int a = 10;
int b = 100;
usint my_ptm = 200;

CryptoContext<DCRTPoly> GenerateBFVrnsContext() {
  usint ptm = my_ptm;
  double sigma = 3.19;
  double rootHermiteFactor = 1.0048;
//  SecurityLevel rootHermiteFactor = HEStd_128_classic;
  size_t count = 100;

  // Set Crypto Parameters
  CryptoContext<DCRTPoly> cryptoContext =
          CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
                  ptm, rootHermiteFactor, sigma, 0, 5, 0, MODE::OPTIMIZED, 3, 30, 55);

  // enable features that you wish to use
  cryptoContext->Enable(PKESchemeFeature::ENCRYPTION);
  cryptoContext->Enable(PKESchemeFeature::SHE);

  //	std::cout << "\np = " <<
  // cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
  //	std::cout << "n = " <<
  // cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()
  /// 2 << std::endl; 	std::cout << "log2 q = " <<
  // log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
  //<< std::endl;

  return cryptoContext;
}

CryptoContext<DCRTPoly> GenerateCKKSContext() {
  usint cyclOrder = 8192;
  usint numPrimes = 2;
  usint scaleExp = 50;
  usint relinWindow = 0;
  int slots = 8;

  // Get CKKS crypto context and generate encryption keys.
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKSWithParamsGen(
          cyclOrder, numPrimes, scaleExp, relinWindow, slots, MODE::OPTIMIZED, 1, 5,
          60, KeySwitchTechnique::GHS);

  cc->Enable(PKESchemeFeature::ENCRYPTION);
  cc->Enable(PKESchemeFeature::SHE);
  cc->Enable(PKESchemeFeature::LEVELEDSHE);

  return cc;
}

CryptoContext<DCRTPoly> GenerateBGVrnsContext() {
  usint cyclOrder = 8192;
  usint numPrimes = 2;
  usint ptm = my_ptm;
  usint relinWindow = 0;

  // Get BGVrns crypto context and generate encryption keys.
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrnsWithParamsGen(
          cyclOrder, numPrimes, ptm, relinWindow, OPTIMIZED, 1, 1, GHS);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  return cc;
}

void BFV_MatrixMul(benchmark::State &state){

  int numRow = 3;
  int numCol = 3;

  usint ptm = my_ptm;
  double sigma = 3.19;
  double rootHermiteFactor = 1.0048;
//  SecurityLevel rootHermiteFactor = HEStd_128_classic;
  size_t count = 100;

  // Set Crypto Parameters
  auto cc =
          CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
                  ptm, rootHermiteFactor, sigma, 0, 5, 0, MODE::OPTIMIZED, 3, 30, 55);

  // enable features that you wish to use
  cc->Enable(PKESchemeFeature::ENCRYPTION);
  cc->Enable(PKESchemeFeature::SHE);

//  usint plaintextModulus = 512;
//  usint relWindow = 8;
//  float stdDev = 4;
//  CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
//          plaintextModulus, 1.6, relWindow, stdDev, 0, 3, 0);
//  cc->Enable(ENCRYPTION);
//  cc->Enable(SHE);

  auto kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);

  auto zeroAlloc = [=]() { return Plaintext(); };

  std::default_random_engine generator;
  std::uniform_int_distribution<int> distribution(a,b);

  Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, numRow, numCol);
  Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, numRow, numCol);

  for(int i=0;i<numRow;i++){
    for (int j=0; j<numCol;j++){
      xP(i, j) = cc->MakeIntegerPlaintext(distribution(generator));
      yP(i, j) = cc->MakeIntegerPlaintext(distribution(generator));
    }
  }

  auto x =
          cc->EncryptMatrix(kp.publicKey, xP);

  auto y =
          cc->EncryptMatrix(kp.publicKey, yP);

  ////////////////////////////////////////////////////////////
  // Linear Regression
  ////////////////////////////////////////////////////////////
  while (state.KeepRunning()) {
    auto result = cc->EvalLinRegression(x, y);
  }

}
BENCHMARK(BFV_MatrixMul)->Unit(benchmark::kMicrosecond);

void BGV_MatrixMul(benchmark::State &state){

  int numRow = 3;
  int numCol = 3;

//  usint m = 512;
//
//  float stdDev = 4;
//  usint size = 4;
//  usint plaintextmodulus = 256;
//  usint relinWindow = 1;

//  shared_ptr<ILDCRTParams<BigInteger>> params =
//          GenerateDCRTParams<BigInteger>(m, size, 30);
//
//  CryptoContext<DCRTPoly> cc =
//          CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(
//                  params, plaintextmodulus, relinWindow, stdDev);
//  cc->Enable(ENCRYPTION);
//  cc->Enable(SHE);
  usint cyclOrder = 8192;
  usint numPrimes = 2;
  usint ptm = my_ptm;
  usint relinWindow = 0;
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrnsWithParamsGen(
          cyclOrder, numPrimes, ptm, relinWindow, OPTIMIZED, 1, 1, GHS);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  LPKeyPair<DCRTPoly> kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);

  auto zeroAlloc = [=]() { return Plaintext(); };

  std::default_random_engine generator;
  std::uniform_int_distribution<int> distribution(a,b);

  Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, numRow, numCol);
  Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, numRow, numCol);

  for(int i=0;i<numRow;i++){
    for (int j=0; j<numCol;j++){
      xP(i, j) = cc->MakeIntegerPlaintext(distribution(generator));
      yP(i, j) = cc->MakeIntegerPlaintext(distribution(generator));
    }
  }

  auto x = cc->EncryptMatrix(kp.publicKey, xP);

  auto y = cc->EncryptMatrix(kp.publicKey, yP);

  ////////////////////////////////////////////////////////////
  // Linear Regression
  ////////////////////////////////////////////////////////////
  while (state.KeepRunning()) {
    auto result = cc->EvalLinRegression(x, y);
  }

}
BENCHMARK(BGV_MatrixMul)->Unit(benchmark::kMicrosecond);


BENCHMARK_MAIN();
