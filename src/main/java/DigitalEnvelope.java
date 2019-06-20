import java.util.Arrays;

public class DigitalEnvelope {

	private String encryptedText;

	private byte[] encryptedKey;

	public DigitalEnvelope(String encryptedText, byte[] encryptedKey) {
		super();
		this.encryptedText = encryptedText;
		this.encryptedKey = encryptedKey;
	}

	public DigitalEnvelope() {

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
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
		DigitalEnvelope other = (DigitalEnvelope) obj;
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
		return "DigitalEnvelope is tuple M = (C1,C2) where C1 is = " + encryptedText + "\n and C2 ="
				+ new String(encryptedKey);
	}

}
