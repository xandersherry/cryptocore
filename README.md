CryptoCore
==========

A cryptographic library for .NET

CryptoCore encapsulates some of the more common symmetric crypto algorithms used by .NET, adding authenticated encryption with an implementation of AES-HMAC and AEAD algorithms from the CodePlex CLRSecurity project by Microsoft, which wraps the CNG algorithms provided by the Cryptographic API:Next Generation now offered by Windows but not yet exposed by the core .NET framework.  

The most important API in the library is Xeres.CryptoCore.SimpleEncryption.  This API is designed to expose the simplest way to securely encrypt data in .NET applications.

It's simple because there are no options. There is a static SimpleEncryption class which will let you generate a secure random key (if you don't have one already) encrypt a string, and then decrypt it again. No algorithms to choose between, no modes of operation to decide on, no MACs to verify, no settings or options to worry about...It's all been taken care of for you, so you can focus on your application, and leave your data encryption to the CrypoCore library.  All you have to worry about is where to securely store your encryption key. 

Installation
=============

You can install from Nuget by running: PM> Install-Package Xeres.CryptoCore
