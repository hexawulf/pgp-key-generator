package com.example.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.*;
import java.security.*;
import java.util.*;
import java.util.Date;

/**
 * PGPKeyGenerator - A tool for generating PGP key pairs in .asc format
 */
public class PGPKeyGenerator {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    
    // Key flag constants - defining these directly since KeyFlags may not be available
    private static final int KEY_FLAG_SIGN_DATA = 0x02;
    private static final int KEY_FLAG_CERTIFY_OTHER = 0x01;
    private static final int KEY_FLAG_ENCRYPT_COMMS = 0x04;
    private static final int KEY_FLAG_ENCRYPT_STORAGE = 0x08;
    
    static {
        Security.addProvider(PROVIDER);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            System.out.println("=== PGP Key Generator ===");
            System.out.println("This tool will create a new PGP key pair");
            System.out.println();
            
            // Get user identity information
            System.out.print("Enter your name: ");
            String name = scanner.nextLine().trim();
            
            System.out.print("Enter your email: ");
            String email = scanner.nextLine().trim();
            
            System.out.print("Enter a comment (optional, press Enter to skip): ");
            String comment = scanner.nextLine().trim();
            
            // Create filename prefix from user's name (lowercase, no spaces)
            String filenamePrefix = name.toLowerCase().replaceAll("\\s+", "") + "_";
            
            // Construct identity
            String identity = name + " <" + email + ">";
            if (!comment.isEmpty()) {
                identity = name + " (" + comment + ") <" + email + ">";
            }
            
            // Get key strength
            System.out.print("Enter key strength (1024, 2048, 4096): ");
            int keySize = 2048; // Default
            try {
                keySize = Integer.parseInt(scanner.nextLine().trim());
                if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
                    System.out.println("Invalid key size. Using default: 2048");
                    keySize = 2048;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Using default key size: 2048");
            }
            
            // Get passphrase
            System.out.print("Enter passphrase for private key: ");
            char[] passphrase = scanner.nextLine().toCharArray();
            
            // Get expiry (in days)
            System.out.print("Key expiry in days (0 for no expiry): ");
            long expiryDays = 0; // Default: no expiry
            try {
                expiryDays = Long.parseLong(scanner.nextLine().trim());
                if (expiryDays < 0) {
                    System.out.println("Invalid expiry. Using default: no expiry");
                    expiryDays = 0;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Using default: no expiry");
            }
            
            // Get output directory
            System.out.print("Enter output directory (press Enter for current directory): ");
            String outputDir = scanner.nextLine().trim();
            if (outputDir.isEmpty()) {
                outputDir = ".";
            }
            
            File directory = new File(outputDir);
            if (!directory.exists()) {
                if (!directory.mkdirs()) {
                    System.out.println("Failed to create directory. Using current directory.");
                    outputDir = ".";
                }
            }
            
            // Generate and export the key pair
            System.out.println("\nGenerating key pair for: " + identity);
            System.out.println("Key strength: " + keySize + " bits");
            System.out.println("This may take a moment...");
            
            PGPKeyRingGenerator keyRingGenerator = generateKeyRingGenerator(
                    identity, passphrase, keySize, expiryDays);
            
            // Get the generated key rings
            PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();
            PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();
            
            // Extract the key IDs for file naming
            PGPPublicKey masterKey = publicKeyRing.getPublicKey();
            String keyId = Long.toHexString(masterKey.getKeyID()).toUpperCase();
            
            // Export the keys using the user's name as a prefix
            String pubKeyFile = outputDir + File.separator + filenamePrefix + "pubkey_" + keyId + ".asc";
            String secKeyFile = outputDir + File.separator + filenamePrefix + "seckey_" + keyId + ".asc";
            
            exportPublicKey(publicKeyRing, pubKeyFile);
            exportSecretKey(secretKeyRing, secKeyFile);
            
            System.out.println("\nKey generation complete!");
            System.out.println("Public key ID: 0x" + keyId);
            System.out.println("Public key exported to: " + pubKeyFile);
            System.out.println("Secret key exported to: " + secKeyFile);
            System.out.println("\nYour secret key is protected by the passphrase you provided.");
            System.out.println("Keep your secret key safe and secure!");
            
        } catch (Exception e) {
            System.err.println("Error generating keys: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    private static PGPKeyRingGenerator generateKeyRingGenerator(
            String identity, char[] passphrase, int keySize, long expiryDays) 
            throws Exception {
            
        // Create the master (signing) key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair signingKeyPair = keyPairGenerator.generateKeyPair();
        
        // Create the encryption subkey pair
        keyPairGenerator.initialize(keySize);
        KeyPair encryptionKeyPair = keyPairGenerator.generateKeyPair();
        
        // Set up the digest calculator
        PGPDigestCalculator sha1DigestCalculator = new BcPGPDigestCalculatorProvider()
                .get(HashAlgorithmTags.SHA1);
        
        // Define when the keys expire
        Date now = new Date();
        Date expiryDate = expiryDays > 0 
                ? new Date(now.getTime() + expiryDays * 24 * 60 * 60 * 1000L) 
                : null;
        
        // Set up the master key - using JcaPGPKeyPair
        PGPKeyPair signingKeyPgpPair = new JcaPGPKeyPair(
                PGPPublicKey.RSA_SIGN, signingKeyPair, now);
        
        // Set up the encryption subkey - using JcaPGPKeyPair
        PGPKeyPair encryptionKeyPgpPair = new JcaPGPKeyPair(
                PGPPublicKey.RSA_ENCRYPT, encryptionKeyPair, now);
        
        // Set up the key encryptor for protecting the secret key with a passphrase
        PBESecretKeyEncryptor secretKeyEncryptor = new BcPBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256)
                .build(passphrase);
        
        // Create the key ring generator
        PGPSignatureSubpacketGenerator masterSubpackets = new PGPSignatureSubpacketGenerator();
        
        // Add signing capabilities to the master key (using our constants instead of KeyFlags)
        masterSubpackets.setKeyFlags(false, KEY_FLAG_SIGN_DATA | KEY_FLAG_CERTIFY_OTHER);
        masterSubpackets.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128
        });
        masterSubpackets.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA224
        });
        
        if (expiryDate != null) {
            masterSubpackets.setKeyExpirationTime(false, 
                    expiryDate.getTime() / 1000 - now.getTime() / 1000);
        }
        
        // Set up the encryption subkey
        PGPSignatureSubpacketGenerator encryptionSubpackets = new PGPSignatureSubpacketGenerator();
        encryptionSubpackets.setKeyFlags(false, KEY_FLAG_ENCRYPT_COMMS | KEY_FLAG_ENCRYPT_STORAGE);
        
        if (expiryDate != null) {
            encryptionSubpackets.setKeyExpirationTime(false, 
                    expiryDate.getTime() / 1000 - now.getTime() / 1000);
        }
        
        // Create the key ring generator with the signing and encryption keys
        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                signingKeyPgpPair,
                identity,
                sha1DigestCalculator,
                masterSubpackets.generate(),
                null,
                new BcPGPContentSignerBuilder(signingKeyPgpPair.getPublicKey().getAlgorithm(), 
                                            HashAlgorithmTags.SHA512),
                secretKeyEncryptor
        );
        
        // Add the encryption subkey
        keyRingGenerator.addSubKey(encryptionKeyPgpPair, encryptionSubpackets.generate(), null);
        
        return keyRingGenerator;
    }

    private static void exportPublicKey(PGPPublicKeyRing publicKeyRing, String fileName) 
            throws IOException {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(new FileOutputStream(fileName))) {
            armoredOut.setHeader("Version", "PGPKeyGenerator v1.0");
            publicKeyRing.encode(armoredOut);
        }
    }

    private static void exportSecretKey(PGPSecretKeyRing secretKeyRing, String fileName) 
            throws IOException {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(new FileOutputStream(fileName))) {
            armoredOut.setHeader("Version", "PGPKeyGenerator v1.0");
            secretKeyRing.encode(armoredOut);
        }
    }
}