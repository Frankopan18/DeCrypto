import java.util.Arrays;

public class DigitalSeal {

	// C1
	private String encryptedText;

	// C2
	private byte[] encryptedKey;

	// C3
	private byte[] encryptedHash;

	public DigitalSeal(String encryptedText, byte[] encryptedKey, byte[] encryptedHash) {
		super();
		this.encryptedText = encryptedText;
		this.encryptedKey = encryptedKey;
		this.encryptedHash = encryptedHash;
	}

	public DigitalSeal() {

	}

	public String getEncryptedText() {
		return encryptedText;
	}

	public void setEncryptedText(String encryptedText) {
		this.encryptedText = encryptedText;
	}

	public byte[] getEncryptedKey() {
		return encryptedKey;
	}

	public void setEncryptedKey(byte[] encryptedKey) {
		this.encryptedKey = encryptedKey;
	}

	public byte[] getEncryptedHash() {
		return encryptedHash;
	}

	public void setEncryptedHash(byte[] encryptedHash) {
		this.encryptedHash = encryptedHash;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(encryptedHash);
		result = prime * result + Arrays.hashCode(encryptedKey);
		result = prime * result + ((encryptedText == null) ? 0 : encryptedText.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DigitalSeal other = (DigitalSeal) obj;
		if (!Arrays.equals(encryptedHash, other.encryptedHash))
			return false;
		if (!Arrays.equals(encryptedKey, other.encryptedKey))
			return false;
		if (encryptedText == null) {
			if (other.encryptedText != null)
				return false;
		} else if (!encryptedText.equals(other.encryptedText))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "DigitalSeal:\nencryptedText=" + encryptedText + "\nencryptedKey=" + new String(encryptedKey)
				+ "\nencryptedHash=" + new String(encryptedHash);
	}
}
