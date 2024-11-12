import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { bootstrapApplication } from '@angular/platform-browser';

@Component({
  selector: 'app-root',
  standalone: true,
  template: `
    <h1>Angular Encrypt/Decrypt</h1>
    <textarea #textToEncrypt placeholder="text to encrypt"></textarea>
    <input #encryptPassword type="password" placeholder="key">
    <button (click)="encryptText(textToEncrypt.value, encryptPassword.value)">Encrypt</button>
    <textarea #textToDecrypt [(ngModel)]="encryptedText" placeholder="text to decrypt"></textarea>
    <input #decryptPassword type="password" placeholder="key">
    <button (click)="decryptText(textToDecrypt.value, decryptPassword.value)">Decrypt</button>
    <textarea readonly [(ngModel)]="decryptedText"></textarea>
  `,
  imports: [FormsModule],
})
export class App {
  encryptedText = '';
  decryptedText = '';

  private readonly algorithm = 'AES-GCM';
  private readonly keyLength = 256;
  private readonly ivLength = 12;
  private readonly saltLength = 16;

  private async deriveKeyFromPassword(
    password: string,
    salt: Uint8Array
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();

    const baseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      baseKey,
      { name: this.algorithm, length: this.keyLength },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async encryptText(plainText: string, password: string) {
    try {
      this.encryptedText = '';
      const encoder = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
      const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));

      const encrypted = await crypto.subtle.encrypt(
        {
          name: this.algorithm,
          iv: iv,
        },
        await this.deriveKeyFromPassword(password, salt),
        encoder.encode(plainText)
      );

      const ivAndCiphertext = new Uint8Array([
        ...salt,
        ...iv,
        ...new Uint8Array(encrypted),
      ]);

      this.encryptedText = btoa(String.fromCharCode(...ivAndCiphertext));
    } catch (error: any) {
      console.error(error);
      alert(error.message);
    }
  }

  async decryptText(encryptedText: string, password: string) {
    try {
      this.decryptedText = '';
      const data = Uint8Array.from(atob(encryptedText), (c) => c.charCodeAt(0));
      const salt = data.slice(0, this.saltLength);
      const iv = data.slice(this.saltLength, this.saltLength + this.ivLength);
      const ciphertext = data.slice(this.saltLength + this.ivLength);

      const key = await this.deriveKeyFromPassword(password, salt);
      const decrypted = await crypto.subtle.decrypt(
        {
          name: this.algorithm,
          iv: iv,
        },
        key,
        ciphertext
      );

      const decoder = new TextDecoder();
      this.decryptedText = decoder.decode(decrypted);
    } catch (error: any) {
      console.error(error);
      alert(error.message);
    }
  }
}

bootstrapApplication(App);
