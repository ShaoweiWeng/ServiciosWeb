package es.upm.etsiinf.sos;

import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUserResponseE;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePassword;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePasswordResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUserResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Login;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.LoginResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Logout;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.PasswordPair;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.User;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Username;

import java.rmi.RemoteException;

public class ClientETSIINFLibrary {
	private static ETSIINFLibraryStub stub;

	public static void main(String[] args) throws Exception {
		stub = new ETSIINFLibraryStub();
		stub._getServiceClient().getOptions().setManageSession(true);
		stub._getServiceClient().engageModule("addressing");

		loginAsAdmin();
		logout();

		loginAsUser("yujie.weng", "yujie.weng1234");
		loginAsUser("yujie.weng", "yujie.weng1234");
		logout();

		loginAsAdmin();
		addNewUser("changePasswordTest");
		addNewUser("deleteUserTest");
		deleteUser("deleteUserTest");
		logout();

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		changePassword("changePasswordTestNewPassword", "changePasswordTestNewPassword");
		logout();
	}

	private static void loginAsAdmin() throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName("admin");
		user.setPwd("admin");
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("Admin login successful");
			} else {
				System.out.println("Admin login failed");
			}
		} catch (RemoteException e) {
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void addNewUser(String userName) throws RemoteException {
		AddUser addUser = new AddUser();
		Username user = new Username();
		user.setUsername(userName);
		addUser.setArgs0(user);

		try {
			AddUserResponseE addUserResponse = stub.addUser(addUser);
			if (addUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " added successfully");
				System.out.println("Password: " + addUserResponse.get_return().getPwd());
			} else {
				System.out.println("Adding user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void loginAsUser(String userName, String password) throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName(userName);
		user.setPwd(password);
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " logged in successfully");
			} else {
				System.out.println("User login failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void logout() throws RemoteException {
		try {
			Logout logout = new Logout();
			stub.logout(logout);
			System.out.println("Logout successful");
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void deleteUser(String userName) throws RemoteException {
		DeleteUser deleteUser = new DeleteUser();
		Username user = new Username();
		user.setUsername(userName);
		deleteUser.setArgs0(user);

		try {
			DeleteUserResponse deleteUserResponse = stub.deleteUser(deleteUser);
			if (deleteUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " deleted successfully");
			} else {
				System.out.println("Deleting user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void changePassword(String oldPassword, String newPassword) throws RemoteException {
		ChangePassword changePassword = new ChangePassword();
		PasswordPair passwordPair = new PasswordPair();
		passwordPair.setOldpwd(oldPassword);
		passwordPair.setNewpwd(newPassword);
		changePassword.setArgs0(passwordPair);

		try {
			ChangePasswordResponse response = stub.changePassword(changePassword);
			if (response.get_return().getResponse()) {
				System.out.println("Password changed successfully");
			} else {
				System.out.println("Changing password failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

}
