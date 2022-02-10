package com.hiramine.smbfilereadusingsmbjtrial;

import android.net.Uri;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.fileinformation.FileStandardInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

import java.io.InputStream;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.util.EnumSet;
import java.util.List;

public class FileReader
{
	// 定数
	private static final String LOGTAG = "FileReader";

	public static final int RESULT_SUCCEEDED                    = 0;
	public static final int RESULT_FAILED_UNKNOWN_HOST          = 1;
	public static final int RESULT_FAILED_NO_ROUTE_TO_HOST      = 2;
	public static final int RESULT_FAILED_LOGON_FAILURE         = 3;
	public static final int RESULT_FAILED_BAD_NETWORK_NAME      = 4;
	public static final int RESULT_FAILED_NOT_FOUND             = 5;
	public static final int RESULT_FAILED_FUNCTION_AUTHENTICATE = 11;
	public static final int RESULT_FAILED_FUNCTION_CONNECTSHARE = 12;
	public static final int RESULT_FAILED_FUNCTION_OPENFILE     = 13;
	public static final int RESULT_FAILED_UNKNOWN               = 99;

	// スレッドの作成と開始
	public void startReading( Handler handler,
							  String strTargetPath,
							  String strUsername,
							  String strPassword )
	{
		// スレッドの作成と開始
		Thread thread = new Thread( () -> threadfuncRead( handler,
														  strTargetPath,
														  strUsername,
														  strPassword ) );
		thread.start();
	}

	// スレッド関数
	private void threadfuncRead( Handler handler,
								 String strTargetPath,
								 String strUsername,
								 String strPassword )
	{
		Log.d( LOGTAG, "Reading thread started." );

		// TargetPathから、HostName,ShareName,Pathを切り出す。
		// smb://hostname/sharename/directory1/directory2/filename
		Uri           uri                = Uri.parse( strTargetPath );
		String        strHostName        = uri.getHost();    // HostNameの切り出し
		List<String>  liststrPathSegment = uri.getPathSegments();
		String        strShareName       = liststrPathSegment.get( 0 );    // パスセグメントの先頭がShareName
		StringBuilder sb                 = new StringBuilder();
		// パスセグメントの先頭以外を「\\」で連結し、Pathを作る
		for( int i = 1; i < liststrPathSegment.size(); i++ )
		{
			if( sb.length() > 0 )
			{
				sb.append( "\\" );
			}
			sb.append( liststrPathSegment.get( i ) );
		}
		String strPath = sb.toString();

		String strDomain = "";    // Domainとして、空文字の他、"WORKGROUP"や適当な文字列など、何を指定しても特に動作変化見られず。

		// 呼び出し元スレッドに返却する用のメッセージ変数の取得
		Message message = Message.obtain( handler );

		try
		{
			// DiskShareの作成
			SmbConfig  smbconfig = SmbConfig.createDefaultConfig();
			SMBClient  smbclient = new SMBClient( smbconfig );
			Connection connection;
			try
			{
				connection = smbclient.connect( strHostName );
			}
			catch( UnknownHostException e )
			{	// 不明なホスト
				message.what = RESULT_FAILED_UNKNOWN_HOST;
				message.obj = null;
				Log.w( LOGTAG, "Reading thread end. : Unknown host." );
				return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
			}
			catch( NoRouteToHostException e )
			{	// ホストへのルートがない
				message.what = RESULT_FAILED_NO_ROUTE_TO_HOST;
				message.obj = null;
				Log.w( LOGTAG, "Reading thread end. : No route to host." );
				return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
			}
			AuthenticationContext authenticationcontext = new AuthenticationContext( strUsername,
																					 strPassword.toCharArray(),
																					 strDomain );
			Session session;
			try
			{
				session = connection.authenticate( authenticationcontext );
			}
			catch( SMBApiException e )
			{
				if( NtStatus.STATUS_LOGON_FAILURE == e.getStatus() )
				{    // Connection#authenticate()の結果「Logon failure」
					message.what = RESULT_FAILED_LOGON_FAILURE;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Logon failure." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // Connection#authenticate()の結果「Logon failure」以外で失敗
					message.what = RESULT_FAILED_FUNCTION_AUTHENTICATE;
					message.obj = null;
					Log.e( LOGTAG, "Reading thread end. : Function authenticate() failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}
			DiskShare diskshare;
			try
			{
				diskshare = (DiskShare)session.connectShare( strShareName );
			}
			catch( SMBApiException e )
			{
				if( NtStatus.STATUS_BAD_NETWORK_NAME == e.getStatus() )
				{    // Session#connectShare()の結果「Bad network name」
					message.what = RESULT_FAILED_BAD_NETWORK_NAME;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Bad network name." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // Session#connectShare()の結果「Bad network name」以外で失敗
					message.what = RESULT_FAILED_FUNCTION_CONNECTSHARE;
					message.obj = null;
					Log.e( LOGTAG, "Reading thread end. : Function connectShare() failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}

			// Fileオープン
			File smbfile;
			try
			{
				smbfile = diskshare.openFile( strPath,
											  EnumSet.of( AccessMask.FILE_READ_DATA ),
											  null,
											  SMB2ShareAccess.ALL,
											  SMB2CreateDisposition.FILE_OPEN,
											  null );
			}
			catch( SMBApiException e )
			{
				if( NtStatus.STATUS_OBJECT_NAME_NOT_FOUND == e.getStatus()	// ファイルがない場合
					|| NtStatus.STATUS_OBJECT_PATH_NOT_FOUND == e.getStatus() )	// フォルダがない場合
				{    // DiskShare#openFile()の結果「Not found」
					message.what = RESULT_FAILED_NOT_FOUND;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Not found." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // DiskShare#openFile()の結果「Not found」以外で失敗
					message.what = RESULT_FAILED_FUNCTION_OPENFILE;
					message.obj = null;
					Log.e( LOGTAG, "Reading thread end. : Function openFile failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}

			// 読み込み
			InputStream inputstream = smbfile.getInputStream();
			long        lLength     = smbfile.getFileInformation( FileStandardInformation.class ).getEndOfFile();
			byte[]      buffer      = new byte[(int)lLength];
			int         bytesRead   = inputstream.read( buffer );
			assert bytesRead == lLength;
			String strText = new String( buffer );    // byte配列を文字列に変換

			// 成功
			message.what = RESULT_SUCCEEDED;
			message.obj = strText;
			Log.d( LOGTAG, "Reading thread end. : Succeeded." );
		}
		catch( Exception e )
		{	// その他の失敗
			message.what = RESULT_FAILED_UNKNOWN;
			message.obj = e.getMessage();
			Log.e( LOGTAG, "Reading thread end. : Failed with unknown cause." );
		}
		finally
		{
			// 呼び出し元スレッドにメッセージ返却
			handler.sendMessage( message );
		}
	}
}
