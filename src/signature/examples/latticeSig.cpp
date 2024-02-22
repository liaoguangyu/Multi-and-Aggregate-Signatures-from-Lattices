//
// Created by xiumaker on 2/18/24.
//

#include "signaturecontext.h"

using namespace lbcrypto;
int main() {
    std::cout << "This is a demo file of the GPV signature scheme" << std::endl
              << std::endl;
    // We generate a signature context and make it a GPV context with ring size,
    // you can also explicitly define ringsize, modulus bitwidth and base
    SignatureContext<Poly> context;
    usint ringsize = 512;
    std::cout << "Used ring size for calculations: " << ringsize << std::endl;
    std::cout << "Generating context for GPV signature" << std::endl << std::endl;
    context.GenerateGPVContext(ringsize, true);//todo:add verifyparameter

    // define plaintext
    GPVPlaintext<Poly> plaintext;
    string pt1 = "This is a test";
    plaintext.SetPlaintext(pt1);

    // Create setup key
    GPVVerificationKey<Poly> A;
    GPVSignKey<Poly> T;
    context.KeyGen(&T, &A);

    // User 1 : Create public key and private key
    GPVVerificationKey<Poly> A_1;
    GPVSignKey<Poly> T_1;
    context.KeyGen(&T_1, &A_1);
    // User 2 : Create public key and private key
    GPVVerificationKey<Poly> A_2;
    GPVSignKey<Poly> T_2;
    context.KeyGen(&T_2, &A_2);


    // User 1 : presign
    GPVSignature<Poly> R_1;
    context.CrsGen(A_1, T, A, &R_1);
    // User 2 : presign
    GPVSignature<Poly> R_2;
    context.CrsGen(A_2, T, A, &R_2);
    //std::cout << Ri.GetSignature().GetRows() << std::endl;


    // User 1 : sign
    GPVSignature<Poly> Sigma_1_Hat, Sigma_1;
    context.Sign(plaintext, T_1, A_1, &Sigma_1_Hat);
    Matrix<Poly> Sigma_1_Matrix = R_1.GetSignature().Mult(Sigma_1_Hat.GetSignature());
    Sigma_1.SetSignature(std::make_shared<Matrix<Poly>>(Sigma_1_Matrix));
    // User 2 : sign
    GPVSignature<Poly> Sigma_2_Hat, Sigma_2;
    context.Sign(plaintext, T_2, A_2, &Sigma_2_Hat);
    Matrix<Poly> Sigma_2_Matrix = R_2.GetSignature().Mult(Sigma_2_Hat.GetSignature());
    Sigma_2.SetSignature(std::make_shared<Matrix<Poly>>(Sigma_2_Matrix));



    // uniform_alloc
    shared_ptr<typename Poly ::Params> params =
            std::static_pointer_cast<GPVSignatureParameters<Poly>>(context.m_params)->GetILParams();
    auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, EVALUATION);
    auto zero_alloc = Poly::Allocator(params, EVALUATION);
    //size_t k = std::static_pointer_cast<GPVSignatureParameters<Poly>>(context.m_params)->GetK();

    // aggregation
    Matrix<Poly> omega_all(zero_alloc, 5, 5, uniform_alloc);
    //std::cout << omega_all.GetData() << std::endl;
    //
    Sigma_1_Matrix.ScalarMult(omega_all(1,1));
    Sigma_2_Matrix.ScalarMult(omega_all(2,2));
    Matrix<Poly> Sigma_1_Alpha = Sigma_1_Matrix.Add(Sigma_2_Matrix);

//    std::cout << Sigma_1_Alpha.GetRows() << std::endl;
//    std::cout << Sigma_1_Alpha.GetCols() << std::endl;

    // std::cout << SigmaIMatrix.GetData() << std::endl;

    // verify
    bool result = context.Verify(plaintext, Sigma_1, A);
    bool result2 = context.Verify(plaintext, Sigma_2, A);

    std::cout << result << result2<< std::endl;



    return 0;
}
