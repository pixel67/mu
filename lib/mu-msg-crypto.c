/*
** Copyright (C) 2012-2018 Dirk-Jan C. Binnema <djcb@djcbsoftware.nl>
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of the GNU General Public License as published by the
** Free Software Foundation; either version 3, or (at your option) any
** later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software Foundation,
** Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
**
*/

#if HAVE_CONFIG_H
#include "config.h"
#endif /*HAVE_CONFIG_H*/

#include <string.h>

#include "mu-msg.h"
#include "mu-msg-priv.h"
#include "mu-msg-part.h"
#include "mu-date.h"

#include <gmime/gmime.h>
#include <gmime/gmime-multipart-signed.h>
#include <gmime/gmime-application-pkcs7-mime.h>


static const char*
get_pubkey_algo_name (GMimePubKeyAlgo algo)
{
	switch (algo) {
	case GMIME_PUBKEY_ALGO_DEFAULT:
		return "default";
	case GMIME_PUBKEY_ALGO_RSA:
		return "RSA";
	case GMIME_PUBKEY_ALGO_RSA_E:
		return "RSA (encryption only)";
	case GMIME_PUBKEY_ALGO_RSA_S:
		return "RSA (signing only)";
	case GMIME_PUBKEY_ALGO_ELG_E:
		return "ElGamal (encryption only)";
	case GMIME_PUBKEY_ALGO_DSA:
		return "DSA";
	case GMIME_PUBKEY_ALGO_ELG:
		return "ElGamal";
	default:
		return "unknown pubkey algorithm";
	}
}

static const gchar*
get_digestkey_algo_name (GMimeDigestAlgo algo)
{
	switch (algo) {
	case GMIME_DIGEST_ALGO_DEFAULT:
		return "default";
	case GMIME_DIGEST_ALGO_MD5:
		return "MD5";
	case GMIME_DIGEST_ALGO_SHA1:
		return "SHA-1";
	case GMIME_DIGEST_ALGO_RIPEMD160:
		return "RIPEMD160";
	case GMIME_DIGEST_ALGO_MD2:
		return "MD2";
	case GMIME_DIGEST_ALGO_TIGER192:
		return "TIGER-192";
	case GMIME_DIGEST_ALGO_HAVAL5160:
		return "HAVAL-5-160";
	case GMIME_DIGEST_ALGO_SHA256:
		return "SHA-256";
	case GMIME_DIGEST_ALGO_SHA384:
		return "SHA-384";
	case GMIME_DIGEST_ALGO_SHA512:
		return "SHA-512";
	case GMIME_DIGEST_ALGO_SHA224:
		return "SHA-224";
	case GMIME_DIGEST_ALGO_MD4:
		return "MD4";
	default:
		return "unknown digest algorithm";
	}
}


/* get data from the 'certificate' */
static char*
get_cert_data (GMimeCertificate *cert)
{
	const char *email, *name, *digest_algo, *pubkey_algo,
		*keyid, *trust;

	email         =  g_mime_certificate_get_email (cert);
	name  = g_mime_certificate_get_name (cert);
	keyid = g_mime_certificate_get_key_id (cert);

	digest_algo  =  get_digestkey_algo_name
		(g_mime_certificate_get_digest_algo (cert));
	pubkey_algo  =  get_pubkey_algo_name
		(g_mime_certificate_get_pubkey_algo (cert));

	switch (g_mime_certificate_get_trust (cert)) {
	case GMIME_TRUST_UNKNOWN:   trust = "unknown"; break;
	case GMIME_TRUST_UNDEFINED: trust = "undefined"; break;
	case GMIME_TRUST_NEVER:     trust = "never"; break;
	case GMIME_TRUST_MARGINAL:  trust = "marginal"; break;
	case GMIME_TRUST_FULL:      trust = "full"; break;
	case GMIME_TRUST_ULTIMATE:  trust = "ultimate"; break;
	default:
		g_return_val_if_reached (NULL);
	}

	return g_strdup_printf (
		"signer:%s, key:%s (%s,%s), trust:%s",
		name ? name : (email ? email :"?"),
		/* email ? email : "?", */
		keyid, pubkey_algo, digest_algo,
		trust);
}


/* get a human-readable report about the signature */
static char*
get_verdict_report (GMimeSignature *msig)
{
	time_t t;
	const char *status, *created, *expires;
	gchar *certdata, *report;
	GMimeSignatureStatus sigstat;

	sigstat = g_mime_signature_get_status (msig);
	if (sigstat & GMIME_SIGNATURE_STATUS_ERROR_MASK)
            status = "error";
	else if (sigstat & GMIME_SIGNATURE_STATUS_RED)
		status = "bad";
	else if ((sigstat & GMIME_SIGNATURE_STATUS_GREEN) ||
                 (sigstat == GMIME_SIGNATURE_STATUS_VALID))
		status = "good";
        else if (sigstat == 0)
            status = "WTF?";
	else {
            g_return_val_if_reached (NULL);
        }
        
	t = g_mime_signature_get_created (msig);
	created = (t == 0 || t == (time_t)-1) ? "?" : mu_date_str ("%x", t);
 
	t = g_mime_signature_get_expires (msig);
	expires = (t == 0 || t == (time_t)-1) ? "?" : mu_date_str ("%x", t);

	certdata = get_cert_data (g_mime_signature_get_certificate (msig));
	report = g_strdup_printf ("%s; created:%s, expires:%s, %s",
				  status, created, expires,
				  certdata ? certdata : "?");
        g_free (certdata);
	return report;
}


static char*
get_signers (GHashTable *signerhash)
{
	GString		*gstr;
	GHashTableIter	 iter;
	const char	*name;

	if (!signerhash || g_hash_table_size(signerhash) == 0)
		return NULL;

	gstr = g_string_new (NULL);
	g_hash_table_iter_init (&iter, signerhash);
	while (g_hash_table_iter_next (&iter, (gpointer)&name, NULL)) {
		if (gstr->len != 0)
			g_string_append_c (gstr, ',');
		gstr = g_string_append (gstr, name);
	}

	return g_string_free (gstr, FALSE);
}


static MuMsgPartSigStatusReport*
get_status_report (GMimeSignatureList *sigs)
{
	int				 i;
	MuMsgPartSigStatus		 status;
	MuMsgPartSigStatusReport	*status_report;
	char				*report;
	GHashTable			*signerhash;

	status	   = MU_MSG_PART_SIG_STATUS_GOOD; /* let's start positive! */
	signerhash = g_hash_table_new (g_str_hash, g_str_equal);

	for (i = 0, report = NULL; i != g_mime_signature_list_length (sigs);
	     ++i) {

		GMimeSignature		*msig;
		GMimeCertificate	*cert;
		GMimeSignatureStatus	 sigstat;
		gchar			*rep;

		msig = g_mime_signature_list_get_signature (sigs, i);
		sigstat = g_mime_signature_get_status (msig);

		/* downgrade our expectations */
		if ((sigstat & GMIME_SIGNATURE_STATUS_ERROR_MASK) &&
		    status != MU_MSG_PART_SIG_STATUS_ERROR)
			status = MU_MSG_PART_SIG_STATUS_ERROR;
		else if ((sigstat & GMIME_SIGNATURE_STATUS_RED) &&
			 status == MU_MSG_PART_SIG_STATUS_GOOD)
			status = MU_MSG_PART_SIG_STATUS_BAD;

		rep  = get_verdict_report (msig);
		report = g_strdup_printf ("%s%s%d: %s",
					  report ? report : "",
					  report ? "; " : "",  i + 1,
					  rep);
		g_free (rep);

		cert = g_mime_signature_get_certificate (msig);
		if (cert && g_mime_certificate_get_name (cert))
			g_hash_table_add (
				signerhash,
				(gpointer)g_mime_certificate_get_name (cert));
	}

	status_report = g_slice_new0 (MuMsgPartSigStatusReport);

	status_report->verdict = status;
	status_report->report  = report;
	status_report->signers = get_signers(signerhash);

	g_hash_table_unref (signerhash);

	return status_report;
}

void
mu_msg_part_sig_status_report_destroy (MuMsgPartSigStatusReport *report)
{
	if (!report)
		return;

	g_free ((char*)report->report);
	g_free ((char*)report->signers);

	g_slice_free (MuMsgPartSigStatusReport, report);
}


static inline void
tag_with_sig_status(GObject *part,
		    MuMsgPartSigStatusReport *report)
{
	g_object_set_data_full
		(part, SIG_STATUS_REPORT, report,
		 (GDestroyNotify)mu_msg_part_sig_status_report_destroy);
}


/* helper functions for detecting signed/encrypted parts */

/* check if mobj's content type is application/pkcs7-mime type=enveloped-data */
gboolean
is_pkcs7_encrypted(GMimeObject *mobj)
{
    return (g_mime_content_type_is_type(g_mime_object_get_content_type(mobj),
					    "application", "pkcs7-mime") &&
            (g_mime_application_pkcs7_mime_get_smime_type((GMimeApplicationPkcs7Mime* )mobj) == GMIME_SECURE_MIME_TYPE_ENVELOPED_DATA));

}

/* check if mobj's content type is application/pkcs7-mime type=signed-data */
gboolean
is_pkcs7_signed(GMimeObject *mobj)
{
	return (g_mime_content_type_is_type(g_mime_object_get_content_type(mobj),
					    "application", "pkcs7-mime") &&
		(g_mime_application_pkcs7_mime_get_smime_type((GMimeApplicationPkcs7Mime* )mobj) == GMIME_SECURE_MIME_TYPE_SIGNED_DATA));

}


/* return if mobj is either multipart/signed or pkcs7 signed-data */
gboolean
is_signed(GMimeObject *mobj)
{
	return (GMIME_IS_MULTIPART_SIGNED(mobj) ||
		is_pkcs7_signed(mobj));
}

/* return if mobj is either multipart/encrypted or pkcs7 encrypted-data */
gboolean
is_encrypted(GMimeObject *mobj)
{
	return (GMIME_IS_MULTIPART_ENCRYPTED(mobj) ||
		is_pkcs7_encrypted(mobj));
}



void
mu_msg_crypto_verify_part (GMimeMultipartSigned *sig, MuMsgOptions opts,
			   GError **err)
{
	/* the signature status */
	MuMsgPartSigStatusReport *report;
	GMimeSignatureList *sigs;

	g_return_if_fail (GMIME_IS_MULTIPART_SIGNED(sig));

	sigs = g_mime_multipart_signed_verify (sig, GMIME_VERIFY_NONE, err);
	if (!sigs) {
		if (err && !*err)
			mu_util_g_set_error (err, MU_ERROR_CRYPTO,
					     "verification failed");
		return;
	}

	report = get_status_report (sigs);
	g_mime_signature_list_clear (sigs);

	/* tag this part with the signature status check */
	tag_with_sig_status(G_OBJECT(sig), report);
}

GMimeObject*
mu_msg_crypto_verify_pkcs7 (GMimeApplicationPkcs7Mime *sig, MuMsgOptions opts,
                            GError **err)
{
    /* the signature status */
    MuMsgPartSigStatusReport *report;
    GMimeSignatureList *sigs;
    GMimeObject *entity;

    g_return_val_if_fail (GMIME_IS_APPLICATION_PKCS7_MIME(sig),NULL);

    entity = NULL;
    sigs = g_mime_application_pkcs7_mime_verify (sig, GMIME_VERIFY_NONE, &entity, err);

    if(!entity) {
        mu_util_g_set_error (err, MU_ERROR_CRYPTO,
                             "pkcs7 decoding failed");
        if(sigs)
            g_mime_signature_list_clear (sigs);

        return NULL;
    } else {
    
        if((opts & MU_MSG_OPTION_VERIFY)) {
            if (!sigs) {
                if (err && !*err)
                    mu_util_g_set_error (err, MU_ERROR_CRYPTO,
                                         "verification failed");
                return entity;
            }

            report = get_status_report (sigs);
            if(report) {
                printf("verify report created.\n");
            }
            g_mime_signature_list_clear (sigs);

            /* tag this part with the signature status check */
            /* FIXME: which mime object should be tagged? */
            tag_with_sig_status(G_OBJECT(entity), report);
            tag_with_sig_status(G_OBJECT(sig), report);

        }
    }
    g_mime_signature_list_clear (sigs);

    return entity;
}


static inline void
check_decrypt_result(GMimeMultipartEncrypted *part, GMimeDecryptResult *res,
		     GError **err)
{
	GMimeSignatureList *sigs;
	MuMsgPartSigStatusReport *report;

	if (res) {
		/* Check if the decrypted part had any embed signatures */
		sigs = res->signatures;
		if (sigs) {
			report = get_status_report (sigs);
			g_mime_signature_list_clear (sigs);

			/* tag this part with the signature status check */
			tag_with_sig_status(G_OBJECT(part), report);
		}
		else {
			if (err && !*err)
				mu_util_g_set_error (err, MU_ERROR_CRYPTO,
						     "verification failed");
		}
		g_object_unref (res);
	}

}


GMimeObject* /* this is declared in mu-msg-priv.h */
mu_msg_crypto_decrypt_part (GMimeMultipartEncrypted *enc, MuMsgOptions opts,
			    MuMsgPartPasswordFunc func, gpointer user_data,
			    GError **err)
{
	GMimeObject *dec;
	GMimeDecryptResult *res;

	g_return_val_if_fail (GMIME_IS_MULTIPART_ENCRYPTED(enc), NULL);

	res = NULL;
	dec = g_mime_multipart_encrypted_decrypt (enc, GMIME_DECRYPT_NONE, NULL,
						  &res, err);
	check_decrypt_result(enc, res, err);

	if (!dec) {
		if (err && !*err)
			mu_util_g_set_error (err, MU_ERROR_CRYPTO,
					     "decryption failed");
		return NULL;
	}

	return dec;
}

static inline void
check_decrypt_result_pkcs7(GMimeApplicationPkcs7Mime *part, GMimeDecryptResult *res,
		     GError **err)
{
    GMimeSignatureList *sigs;
    MuMsgPartSigStatusReport *report;

    if (res) {
        /* Check if the decrypted part had any embed signatures */
        /* don't complain if it doesn't. FIXME: S/MIME encrypted mails
         * don't have signatures as part of the encrypted data. the
         * signed content is inside as separate mime objects. */
        sigs = g_mime_decrypt_result_get_signatures (res);
        if (sigs) {
            report = get_status_report (sigs);
            g_mime_signature_list_clear (sigs);

            /* tag this part with the signature status check */
            tag_with_sig_status(G_OBJECT(part), report);
        }

        g_object_unref (res);
    }

}


GMimeObject*  /* this is declared in mu-msg-priv.h */
mu_msg_crypto_decrypt_pkcs7 (GMimeApplicationPkcs7Mime *enc,
                             MuMsgOptions opts,
                             MuMsgPartPasswordFunc func, gpointer user_data,
                             GError **err)
{

    GMimeObject *dec;
    GMimeDecryptResult *res;

    g_return_val_if_fail (GMIME_IS_APPLICATION_PKCS7_MIME(enc), NULL);

    res = NULL;
    dec = g_mime_application_pkcs7_mime_decrypt (enc, GMIME_DECRYPT_NONE, NULL,
                                              &res, err);
    check_decrypt_result_pkcs7(enc, res, err);

    if (!dec) {
        if (err && !*err) {
            mu_util_g_set_error (err, MU_ERROR_CRYPTO,
                                 "decryption failed");
        }
        return NULL;
    }

    return dec;

}
