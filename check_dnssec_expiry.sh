#!/usr/bin/env bash


# Parse the input options
while getopts ":z:w:c:r:f:" opt; do
  case $opt in
    z)
      zone=$OPTARG
      ;;
    w)
      warning=$OPTARG
      ;;
    c)
      critical=$OPTARG
      ;;
    r)
      resolver=$OPTARG
      ;;
    f)
      alwaysFailingDomain=$OPTARG
      ;;
  esac
done


# Check if we got a zone to validate - fail hard if not
if [[ -z $zone ]]; then
	echo "Missing zone to test - please provide a zone via the -z parameter."
	exit 3
fi

# Check if we got warning/critical percentage values, use defaults if not
if [[ -z $warning ]]; then
	warning=20
fi
if [[ -z $critical ]]; then
	critical=10
fi


# Use Google's 8.8.8.8 resolver as fallback if none is provided
if [[ -z $resolver ]]; then
	resolver="8.8.8.8"
fi

if [[ -z $alwaysFailingDomain ]]; then
	alwaysFailingDomain="dnssec-failed.org"
fi



# Check the resolver to properly validate DNSSEC at all (if he doesn't, every further test is futile and a waste of bandwith)
checkResolverDoesDnssecValidation=$(dig +nocmd +nostats +noquestion $alwaysFailingDomain @${resolver} | grep "opcode: QUERY" | grep "status: SERVFAIL")
if [[ -z $checkResolverDoesDnssecValidation ]]; then
	echo "WARNING: Resolver seems to not validate DNSSEC signatures - going further seems useless right now."
	exit 1
fi

# Check if the resolver delivers an answer for the domain to test
checkDomainResolvableWithDnssecEnabledResolver=$(dig +short @${resolver} A $zone)
if [[ -z $checkDomainResolvableWithDnssecEnabledResolver ]]; then

	checkDomainResolvableWithDnssecValidationExplicitelyDisabled=$(dig +short @${resolver} A $zone +cd)

	if [[ ! -z $checkDomainResolvableWithDnssecValidationExplicitelyDisabled ]]; then
		echo "CRITICAL: The domain $zone can be validated without DNSSEC validation - but will fail on resolvers that do validate DNSSEC."
		exit 2
	else
		echo "CRITICAL: The domain $zone cannot be resolved via $resolver as resolver while DNSSEC validation is active."
		exit 2
	fi
#else
#	echo "OK: $zone is resolvable on $resolver - lucky you!"
fi

# Check if the domain is DNSSEC signed at all
# (and emerge a WARNING in that case, since this check is about testing DNSSEC being "present" and valid which is not the case for an unsigned zone)
checkZoneIsSignedAtAll=$( dig $zone @$resolver DS +short )
if [[ -z $checkZoneIsSignedAtAll ]]; then
	echo "WARNING: Zone $zone seems to be unsigned (= resolvable, but no DNSSEC involved at all)"
	exit 1
fi

# Get the RRSIG entry and extract the date out of it
expiryDateOfSignature=$( dig @$resolver A $zone +dnssec | grep RRSIG | awk '{print $9}')
checkValidityOfExpirationTimestamp=$( echo $expiryDateOfSignature | egrep '[0-9]{14}')
if [[ -z $checkValidityOfExpirationTimestamp ]]; then
	echo "UNKNOWN: Something went wrong while checking the expiration of the RRSIG entry - investigate please".
	echo 3
fi

inceptionDateOfSignature=$( dig @$resolver A $zone +dnssec | grep RRSIG | awk '{print $10}')
checkValidityOfInceptionTimestamp=$( echo $inceptionDateOfSignature | egrep '[0-9]{14}')
if [[ -z $checkValidityOfInceptionTimestamp ]]; then
	echo "UNKNOWN: Something went wrong while checking the inception date of the RRSIG entry - investigate please".
	echo 3
fi

# Fiddle out the expiry and inceptiondate of the signature to have a base to do some calculations afterwards
expiryDateAsString="${expiryDateOfSignature:0:4}-${expiryDateOfSignature:4:2}-${expiryDateOfSignature:6:2} ${expiryDateOfSignature:8:2}:${expiryDateOfSignature:10:2}:00"
expiryDateOfSignatureAsUnixTime=$( date -u -d "$expiryDateAsString" +"%s" 2>/dev/null )
if [[ $? -ne 0 ]]; then
	# if we come to this place, something must have gone wrong converting the date-string. This can happen as e.g. MacOS X and Linux don't behave the same way in this topic...
	expiryDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$expiryDateAsString" +"%s" )
fi
inceptionDateAsString="${inceptionDateOfSignature:0:4}-${inceptionDateOfSignature:4:2}-${inceptionDateOfSignature:6:2} ${inceptionDateOfSignature:8:2}:${inceptionDateOfSignature:10:2}:00"
inceptionDateOfSignatureAsUnixTime=$( date -u -d "$inceptionDateAsString" +"%s" 2>/dev/null )
if [[ $? -ne 0 ]]; then
	# if we come to this place, something must have gone wrong converting the date-string. This can happen as e.g. MacOS X and Linux don't behave the same way in this topic...
	inceptionDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$inceptionDateAsString" +"%s" )
fi


# calculate the remaining lifetime of the signature
now=$(date +"%s")
totalLifetime=$( expr $expiryDateOfSignatureAsUnixTime - $inceptionDateOfSignatureAsUnixTime)
remainingLifetimeOfSignature=$( expr $expiryDateOfSignatureAsUnixTime - $now)
remainingPercentage=$( expr "100" \* $remainingLifetimeOfSignature / $totalLifetime)
#echo "inception    = $inceptionDateOfSignatureAsUnixTime"
#echo "expiry       = $expiryDateOfSignatureAsUnixTime"
#echo "total lt     = $totalLifetime"

#echo "now          = $now"
#echo "remaining lt = $remainingLifetimeOfSignature"
#echo "remaining %  = $remainingPercentage"


# determine if we need to alert, and if so, how loud to cry, depending on warning/critial threshholds provided
if [[ $remainingPercentage -lt $critical ]]; then
	echo "CRITICAL: DNSSEC signature for $zone is very short before expiration! ($remainingPercentage% remaining) | sig_lifetime=$remainingLifetimeOfSignature  sig_lifetime_percentage=$remainingPercentage%;$warning;$critical"
	exit 2
elif [[ $remainingPercentage -lt $warning ]]; then
	echo "WARNING: DNSSEC signature for $zone is short before expiration! ($remainingPercentage% remaining) | sig_lifetime=$remainingLifetimeOfSignature  sig_lifetime_percentage=$remainingPercentage%;$warning;$critical"
	exit 1
else
	echo "OK: DNSSEC signatures for $zone seem to be valid and not expired ($remainingPercentage% remaining) | sig_lifetime=$remainingLifetimeOfSignature  sig_lifetime_percentage=$remainingPercentage%;$warning;$critical"
	exit 0
fi