import java.util.Arrays;

public class DigitalSignature {

	private String clearText;

	private byte[] encryptedHash;

	public DigitalSignature(String clearText, byte[] encryptedHash) {
		super();
		this.clearText = clearText;
		this.encryptedHash = encryptedHash;
	}

	public DigitalSignature() {

	}

	public String getClearText() {
		return clearText;
	}

	public void setClearText(String clearText) {
		this.clearText = clearText;
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
		result = prime * result + ((clearText == null) ? 0 : clearText.hashCode());
		result = prime * result + Arrays.hashCode(encryptedHash);
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
		DigitalSignature other = (DigitalSignature) obj;
		if (clearText == null) {
			if (other.clearText != null)
				return false;
		} else if (!clearText.equals(other.clearText))
			return false;
		if (!Arrays.equals(encryptedHash, other.encryptedHash))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Digital signature is:\nP = " + clearText + "\nH(P) = " + new String(encryptedHash);
	}

}
