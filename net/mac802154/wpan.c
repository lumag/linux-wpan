/*
 * Copyright 2007, 2008, 2009 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/rculist.h>
#include <linux/random.h>
#include <linux/crc-ccitt.h>
#include <linux/nl802154.h>
#include <linux/interrupt.h>

#include <net/rtnetlink.h>
#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>
#include <net/ieee802154.h>
#include <net/wpan-phy.h>

#include "mac802154.h"
#include "mib.h"

static netdev_tx_t mac802154_wpan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mac802154_sub_if_data *priv;
	u8 chan, page;

	priv = netdev_priv(dev);

	spin_lock_bh(&priv->mib_lock);
	chan = priv->chan;
	page = priv->page;
	spin_unlock_bh(&priv->mib_lock);

	if (chan == (u8)-1 || chan >= 27 || page >= IEEE802154_WPAN_NUM_PAGES)
		return NETDEV_TX_OK;

	skb->skb_iif = dev->ifindex;
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	return mac802154_tx(priv->hw, skb, page, chan);
}

static int mac802154_wpan_ioctl(struct net_device *dev, struct ifreq *ifr,
		int cmd)
{
	struct mac802154_sub_if_data *priv = netdev_priv(dev);
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;
	int err = -ENOIOCTLCMD;

	spin_lock_bh(&priv->mib_lock);

	switch (cmd) {
	case SIOCGIFADDR:
		if (priv->pan_id == IEEE802154_PANID_BROADCAST ||
		    priv->short_addr == IEEE802154_ADDR_BROADCAST) {
			err = -EADDRNOTAVAIL;
			break;
		}

		sa->family = AF_IEEE802154;
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = priv->pan_id;
		sa->addr.short_addr = priv->short_addr;

		err = 0;
		break;
	case SIOCSIFADDR:
		dev_warn(&dev->dev,
			"Using DEBUGing ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF) {
			err = -EINVAL;
			break;
		}

		priv->pan_id = sa->addr.pan_id;
		priv->short_addr = sa->addr.short_addr;
		err = 0;
		break;
	}
	spin_unlock_bh(&priv->mib_lock);
	return err;
}

static int mac802154_wpan_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;

	/* FIXME: validate addr */
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	mac802154_dev_set_ieee_addr(dev);

	return 0;
}

static inline void mac802154_haddr_copy_swap(u8 *dest, const u8 *src)
{
	int i;
	for (i = 0; i < IEEE802154_ADDR_LEN; i++)
		dest[IEEE802154_ADDR_LEN - i - 1] = src[i];
}

static int mac802154_header_create(struct sk_buff *skb,
			   struct net_device *dev,
			   unsigned short type, const void *_daddr,
			   const void *_saddr, unsigned len)
{
	u8 head[MAC802154_MAX_MHR_SIZE] = {};
	int pos = 2;

	u16 fc;
	const struct ieee802154_addr *saddr = _saddr;
	const struct ieee802154_addr *daddr = _daddr;
	struct ieee802154_addr dev_addr;
	struct mac802154_sub_if_data *priv = netdev_priv(dev);

	fc = mac_cb_type(skb);
	if (mac_cb_is_ackreq(skb))
		fc |= IEEE802154_FC_ACK_REQ;

	head[pos++] = mac_cb(skb)->seq; /* DSN/BSN */

	if (!daddr)
		return -EINVAL;

	if (!saddr) {
		spin_lock_bh(&priv->mib_lock);
		if (priv->short_addr == IEEE802154_ADDR_BROADCAST ||
		    priv->short_addr == IEEE802154_ADDR_UNDEF ||
		    priv->pan_id == IEEE802154_PANID_BROADCAST) {
			dev_addr.addr_type = IEEE802154_ADDR_LONG;
			memcpy(dev_addr.hwaddr, dev->dev_addr,
					IEEE802154_ADDR_LEN);
		} else {
			dev_addr.addr_type = IEEE802154_ADDR_SHORT;
			dev_addr.short_addr = priv->short_addr;
		}

		dev_addr.pan_id = priv->pan_id;
		saddr = &dev_addr;

		spin_unlock_bh(&priv->mib_lock);
	}

	if (daddr->addr_type != IEEE802154_ADDR_NONE) {
		fc |= (daddr->addr_type << IEEE802154_FC_DAMODE_SHIFT);

		head[pos++] = daddr->pan_id & 0xff;
		head[pos++] = daddr->pan_id >> 8;

		if (daddr->addr_type == IEEE802154_ADDR_SHORT) {
			head[pos++] = daddr->short_addr & 0xff;
			head[pos++] = daddr->short_addr >> 8;
		} else {
			mac802154_haddr_copy_swap(head + pos, daddr->hwaddr);
			pos += IEEE802154_ADDR_LEN;
		}
	}

	if (saddr->addr_type != IEEE802154_ADDR_NONE) {
		fc |= (saddr->addr_type << IEEE802154_FC_SAMODE_SHIFT);

		if ((saddr->pan_id == daddr->pan_id) &&
		    (saddr->pan_id != IEEE802154_PANID_BROADCAST))
			/* PANID compression/ intra PAN */
			fc |= IEEE802154_FC_INTRA_PAN;
		else {
			head[pos++] = saddr->pan_id & 0xff;
			head[pos++] = saddr->pan_id >> 8;
		}

		if (saddr->addr_type == IEEE802154_ADDR_SHORT) {
			head[pos++] = saddr->short_addr & 0xff;
			head[pos++] = saddr->short_addr >> 8;
		} else {
			mac802154_haddr_copy_swap(head + pos, saddr->hwaddr);
			pos += IEEE802154_ADDR_LEN;
		}
	}

	head[0] = fc;
	head[1] = fc >> 8;

	memcpy(skb_push(skb, pos), head, pos);

	return pos;
}

static int mac802154_header_parse(const struct sk_buff *skb,
		unsigned char *haddr)
{
	const u8 *hdr = skb_mac_header(skb), *tail = skb_tail_pointer(skb);
	struct ieee802154_addr *addr = (struct ieee802154_addr *)haddr;
	u16 fc;
	int da_type;

	if (hdr + 3 > tail)
		goto malformed;

	fc = hdr[0] | (hdr[1] << 8);

	hdr += 3;

	da_type = IEEE802154_FC_DAMODE(fc);
	addr->addr_type = IEEE802154_FC_SAMODE(fc);

	switch (da_type) {
	case IEEE802154_ADDR_NONE:
		if (fc & IEEE802154_FC_INTRA_PAN)
			goto malformed;
		break;

	case IEEE802154_ADDR_LONG:
		if (hdr + 2 > tail)
			goto malformed;
		if (fc & IEEE802154_FC_INTRA_PAN) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE802154_ADDR_LEN > tail)
			goto malformed;
		hdr += IEEE802154_ADDR_LEN;
		break;

	case IEEE802154_ADDR_SHORT:
		if (hdr + 2 > tail)
			goto malformed;
		if (fc & IEEE802154_FC_INTRA_PAN) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;
		hdr += 2;
		break;

	default:
		goto malformed;

	}

	switch (addr->addr_type) {
	case IEEE802154_ADDR_NONE:
		break;

	case IEEE802154_ADDR_LONG:
		if (hdr + 2 > tail)
			goto malformed;
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE802154_ADDR_LEN > tail)
			goto malformed;
		mac802154_haddr_copy_swap(addr->hwaddr, hdr);
		hdr += IEEE802154_ADDR_LEN;
		break;

	case IEEE802154_ADDR_SHORT:
		if (hdr + 2 > tail)
			goto malformed;
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;
		addr->short_addr = hdr[0] | (hdr[1] << 8);
		hdr += 2;
		break;

	default:
		goto malformed;

	}

	return sizeof(struct ieee802154_addr);

malformed:
	pr_debug("(%s): malformed packet\n", __func__);
	return 0;
}

static struct header_ops mac802154_header_ops = {
	.create		= mac802154_header_create,
	.parse		= mac802154_header_parse,
};

static const struct net_device_ops mac802154_wpan_ops = {
	.ndo_open		= mac802154_slave_open,
	.ndo_stop		= mac802154_slave_close,
	.ndo_start_xmit		= mac802154_wpan_xmit,
	.ndo_do_ioctl		= mac802154_wpan_ioctl,
	.ndo_set_mac_address	= mac802154_wpan_mac_addr,
};

void mac802154_wpan_setup(struct net_device *dev)
{
	struct mac802154_sub_if_data *priv;

	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);
	dev->hard_header_len	= MAC802154_MAX_MHR_SIZE;
	dev->header_ops		= &mac802154_header_ops;
	dev->needed_tailroom	= 2; /* FCS */
	dev->mtu		= IEEE802154_MTU;
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE802154;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;

	dev->destructor		= free_netdev;
	dev->netdev_ops		= &mac802154_wpan_ops;
	dev->ml_priv		= &mac802154_mlme_wpan.wpan_ops;

	priv			= netdev_priv(dev);
	priv->type		= IEEE802154_DEV_WPAN;

	priv->chan = -1; /* not initialized */
	priv->page = 0; /* for compat */

	spin_lock_init(&priv->mib_lock);

	get_random_bytes(&priv->bsn, 1);
	get_random_bytes(&priv->dsn, 1);

	priv->pan_id = IEEE802154_PANID_BROADCAST;
	priv->short_addr = IEEE802154_ADDR_BROADCAST;
}

static int mac802154_process_data(struct net_device *dev, struct sk_buff *skb)
{
	if (in_interrupt())
		return netif_rx(skb);
	else
		return netif_rx_ni(skb);
}

static int mac802154_subif_frame(struct mac802154_sub_if_data *sdata,
		struct sk_buff *skb)
{
	pr_debug("(%s): getting packet via slave interface %s\n",
				__func__, sdata->dev->name);

	spin_lock_bh(&sdata->mib_lock);

	switch (mac_cb(skb)->da.addr_type) {
	case IEEE802154_ADDR_NONE:
		if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_NONE)
			/* FIXME: check if we are PAN coordinator :) */
			skb->pkt_type = PACKET_OTHERHOST;
		else
			/* ACK comes with both addresses empty */
			skb->pkt_type = PACKET_HOST;
		break;
	case IEEE802154_ADDR_LONG:
		if (mac_cb(skb)->da.pan_id != sdata->pan_id &&
		    mac_cb(skb)->da.pan_id != IEEE802154_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (!memcmp(mac_cb(skb)->da.hwaddr, sdata->dev->dev_addr,
					IEEE802154_ADDR_LEN))
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	case IEEE802154_ADDR_SHORT:
		if (mac_cb(skb)->da.pan_id != sdata->pan_id &&
		    mac_cb(skb)->da.pan_id != IEEE802154_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (mac_cb(skb)->da.short_addr ==
					IEEE802154_ADDR_BROADCAST)
			skb->pkt_type = PACKET_BROADCAST;
		else if (mac_cb(skb)->da.short_addr == sdata->short_addr)
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	}

	spin_unlock_bh(&sdata->mib_lock);

	skb->dev = sdata->dev;

	sdata->dev->stats.rx_packets++;
	sdata->dev->stats.rx_bytes += skb->len;

	if (skb->pkt_type == PACKET_HOST && mac_cb_is_ackreq(skb) &&
			!(sdata->hw->hw.flags & IEEE802154_HW_AACK))
		dev_warn(&sdata->dev->dev,
			"ACK requested, however AACK not supported.\n");

	switch (mac_cb_type(skb)) {
	case IEEE802154_FC_TYPE_DATA:
		return mac802154_process_data(sdata->dev, skb);
	case IEEE802154_FC_TYPE_BEACON:
	case IEEE802154_FC_TYPE_ACK:
	case IEEE802154_FC_TYPE_MAC_CMD:
		return mac802154_process_cmd(sdata->dev, skb);
	default:
		pr_warning("ieee802154: bad frame received (type = %d)\n",
				mac_cb_type(skb));
		kfree_skb(skb);
		return NET_RX_DROP;
	}
}

static int mac802154_fetch_skb_u8(struct sk_buff *skb, u8 *dest)
{
	if (!pskb_may_pull(skb, 1))
		return -EINVAL;

	*dest = skb->data[0];
	skb_pull(skb, 1);

	return 0;
}

static int mac802154_fetch_skb_u16(struct sk_buff *skb, u16 *dest)
{
	if (!pskb_may_pull(skb, 2))
		return -EINVAL;

	*dest = skb->data[0] + (skb->data[1] << 8);
	skb_pull(skb, 2);

	return 0;
}

static int mac802154_fetch_skb_u64(struct sk_buff *skb, u8 *dest)
{
	int i;

	if (!pskb_may_pull(skb, IEEE802154_ADDR_LEN))
		return -EINVAL;

	for (i = 0; i < IEEE802154_ADDR_LEN; i++)
		dest[IEEE802154_ADDR_LEN - i - 1] = skb->data[i];
	skb_pull(skb, IEEE802154_ADDR_LEN);

	return 0;
}

static int parse_frame_start(struct sk_buff *skb)
{
	u8 *head = skb->data;
	u16 fc;

	if (!pskb_may_pull(skb, 3)) {
		pr_debug("(%s): frame size %d bytes is too short\n",
					__func__, skb->len);
		goto exit_error;
	}

	mac802154_fetch_skb_u16(skb, &fc);
	mac802154_fetch_skb_u8(skb, &mac_cb(skb)->seq);

	pr_debug("(%s): %04x dsn%02x\n", __func__, fc, head[2]);

	mac_cb(skb)->flags = IEEE802154_FC_TYPE(fc);

	if (fc & IEEE802154_FC_ACK_REQ) {
		pr_debug("(%s): ACKNOWLEDGE required\n", __func__);
		mac_cb(skb)->flags |= MAC_CB_FLAG_ACKREQ;
	}

	if (fc & IEEE802154_FC_SECEN)
		mac_cb(skb)->flags |= MAC_CB_FLAG_SECEN;

	if (fc & IEEE802154_FC_INTRA_PAN)
		mac_cb(skb)->flags |= MAC_CB_FLAG_INTRAPAN;

	/* TODO */
	if (mac_cb_is_secen(skb)) {
		pr_info("security support is not implemented\n");
		goto exit_error;
	}

	mac_cb(skb)->sa.addr_type = IEEE802154_FC_SAMODE(fc);
	if (mac_cb(skb)->sa.addr_type == IEEE802154_ADDR_NONE)
		pr_debug("(%s): src addr_type is NONE\n", __func__);

	mac_cb(skb)->da.addr_type = IEEE802154_FC_DAMODE(fc);
	if (mac_cb(skb)->da.addr_type == IEEE802154_ADDR_NONE)
		pr_debug("(%s): dst addr_type is NONE\n", __func__);

	if (IEEE802154_FC_TYPE(fc) == IEEE802154_FC_TYPE_ACK) {
		/* ACK can only have NONE-type addresses */
		if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_NONE ||
		    mac_cb(skb)->da.addr_type != IEEE802154_ADDR_NONE)
			goto exit_error;
	}

	if (mac_cb(skb)->da.addr_type != IEEE802154_ADDR_NONE) {
		if (mac802154_fetch_skb_u16(skb, &mac_cb(skb)->da.pan_id))
			goto exit_error;

		if (mac_cb_is_intrapan(skb)) { /* ! panid compress */
			pr_debug("(%s): src IEEE802154_FC_INTRA_PAN\n",
					__func__);
			mac_cb(skb)->sa.pan_id = mac_cb(skb)->da.pan_id;
			pr_debug("(%s): src PAN address %04x\n",
					__func__, mac_cb(skb)->sa.pan_id);
		}

		pr_debug("(%s): dst PAN address %04x\n",
				__func__, mac_cb(skb)->da.pan_id);

		if (mac_cb(skb)->da.addr_type == IEEE802154_ADDR_SHORT) {
			if (mac802154_fetch_skb_u16(skb,
						&mac_cb(skb)->da.short_addr))
				goto exit_error;
			pr_debug("(%s): dst SHORT address %04x\n",
					__func__, mac_cb(skb)->da.short_addr);

		} else {
			if (mac802154_fetch_skb_u64(skb,
						mac_cb(skb)->da.hwaddr))
				goto exit_error;
			pr_debug("(%s): dst hardware addr\n", __func__);
		}
	}

	if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_NONE) {
		pr_debug("(%s): got src non-NONE address\n", __func__);
		if (!(mac_cb_is_intrapan(skb))) { /* ! panid compress */
			if (mac802154_fetch_skb_u16(skb,
						&mac_cb(skb)->sa.pan_id))
				goto exit_error;
			pr_debug("(%s): src IEEE802154_FC_INTRA_PAN\n",
					__func__);
		}

		if (mac_cb(skb)->sa.addr_type == IEEE802154_ADDR_SHORT) {
			if (mac802154_fetch_skb_u16(skb,
						&mac_cb(skb)->sa.short_addr))
				goto exit_error;
			pr_debug("(%s): src IEEE802154_ADDR_SHORT\n",
					__func__);
		} else {
			if (mac802154_fetch_skb_u64(skb,
					mac_cb(skb)->sa.hwaddr))
				goto exit_error;
			pr_debug("(%s): src hardware addr\n", __func__);
		}
	}

	return 0;

exit_error:
	return -EINVAL;
}

void mac802154_wpans_rx(struct mac802154_priv *priv, struct sk_buff *skb)
{
	int ret;
	struct mac802154_sub_if_data *sdata;
	struct sk_buff *skb2;

	ret = parse_frame_start(skb); /* 3 bytes pulled after this */
	if (ret) {
		pr_debug("(%s): Got invalid frame\n", __func__);
		return;
	}

	pr_debug("(%s): frame %d\n", __func__, mac_cb_type(skb));

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &priv->slaves, list)
	{
		if (sdata->type != IEEE802154_DEV_WPAN)
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2)
			mac802154_subif_frame(sdata, skb2);
	}

	rcu_read_unlock();
}
