import iam
import s3
import RDS
import Documentdb_Neptune
import dynamodb
import redshift
import kms
import vpc

if __name__ == "__main__":
    iam.run()
    s3.run()
    vpc.run()
    kms.run()
    RDS.run()
    Documentdb_Neptune.run()
    dynamodb.run()
    redshift.run()
