from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Sport, Base, Equipment, User

engine = create_engine('sqlite:///sportscatalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


User1 = User(name="Danny Ng", email="ngdanny332@gmail.com")
session.add(User1)
session.commit()

myFirstSport = Sport(user_id=1, name = "Snowboarding")
session.add(myFirstSport)
session.commit()

equipment1 = Equipment(user_id=1, name="Board", description="Burton Custom Board",
                     price="$500.00", sport=myFirstSport)
session.add(equipment1)
session.commit()

equipment2 = Equipment(user_id=1, name="Goggles", description="Oakley O2 Goggles",
                     price="$150.00", sport=myFirstSport)
session.add(equipment2)
session.commit()

equipment3 = Equipment(user_id=1, name="bindings", description="Burton K2 Bindings",
                     price="$175.00", sport=myFirstSport)
session.add(equipment3)
session.commit()

mySecondSport = Sport(user_id=1, name = "Skiing")
session.add(mySecondSport)
session.commit()

skiequipment1 = Equipment(user_id=1, name="Ski", description="Head Cross Country Skis",
                     price="$500.00", sport=mySecondSport)
session.add(skiequipment1)
session.commit()

skiequipment2 = Equipment(user_id=1, name="Goggles", description="Oakley O2 Goggles",
                     price="$150.00", sport=mySecondSport)
session.add(skiequipment2)
session.commit()

skiequipment3 = Equipment(user_id=1, name="Ski Poles", description="Head Ski Poles",
                     price="$175.00", sport=mySecondSport)
session.add(skiequipment3)

print("Database info added!")
