"use strict";

var Promise = require( "bluebird" );

var exec = Promise.promisify( require( "child_process" ).exec );
var isWindows = ( require( "os" ).platform().indexOf( "win32" ) >= 0 );

function isAdmin() {
	return new Promise( function( resolve, reject ) {
		if( !isWindows ) {
			resolve( false );
			return;
		}

		exec( "net session" )
			.then( function( result ) {
				resolve( true );
			} )
			.catch( function( error ) {
				if( error.message.match( /Access is denied/ ) ) {
					resolve( false );
				} else {
					reject( error );
				}
			} );
	} );
}

module.exports = isAdmin;
