package es.upm.etsiinf.sos.model.xsd;

public class MyUser {

	private String userName;
	private String password;

	public MyUser(String userName, String password) {
		this.userName = userName;
		this.password = password;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof MyUser) {
			MyUser user = (MyUser) obj;
			return user.getUserName().equals(this.userName) && user.getPassword().equals(this.password);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return userName.hashCode() + password.hashCode();
	}
}
