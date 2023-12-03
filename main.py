import iam
import s3
import RDS
import Documentdb_Neptune
import dynamodb_security_checks
import redshift_security_checks
import kms
import vpc

if __name__ == "__main__":
    iam.run()
    s3.run()
    vpc.run()
    kms.run()
    Documentdb_Neptune.run()
    dynamodb_security_checks.run()
    redshift_security_checks.run()
